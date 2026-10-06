import json
from zipfile import ZipFile
import pytest
from fastapi import HTTPException
from sqlalchemy import select, func
from app import main, validator_client, validator_api, deployment_bundle
from app.deployment_bundle import validate_bundle, file_digest
from app.remediation_validation import classify_static, deployment_manifest, validation_result
from app.models import RemediationExecution
from test_remediation_workflow_routes import workflow, candidate

@pytest.mark.parametrize('name,status,expected', [('source_mapping','PASS','PASS'),('intended_changes','WARNING_UNVERIFIED','WARNING_UNVERIFIED'),('trivy_config_rescan','FAIL','WARNING_UNVERIFIED'),('helm_lint','NOT RUN','WARNING_UNVERIFIED'),('helm_lint','FAIL','BLOCKING'),('change_scope','FAIL','BLOCKING'),('candidate_integrity','FAIL','BLOCKING')])
def test_static_classifications(name,status,expected):
    result=classify_static({'checks':{name:{'status':status}}})
    assert result['status']==expected and result['runtime_eligible']==(expected!='BLOCKING')

@pytest.mark.parametrize("has_render", [True, False])
def test_exact_candidate_manifest_adapter_and_integrity(tmp_path, has_render):
    source=tmp_path/'source'; source.mkdir()
    (source/'Chart.yaml').write_text('apiVersion: v2\nname: demo\nversion: 1.0.0\n')
    for name in ('values.yaml','override.yaml'): (source/name).write_text('enabled: true\n')
    path=tmp_path/'candidate.zip'
    rendered='apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\n' if has_render else ''
    with ZipFile(path,'w') as archive:
        for name in ('Chart.yaml','values.yaml','override.yaml'): archive.write(source/name,'candidate/'+name)
        archive.writestr('rendered.yaml',rendered)
        archive.writestr('documentation/remediation/summary.json','{}')
    with ZipFile(path,'a') as archive:
        manifest=deployment_manifest(archive,candidate_dir=source,values_files=['values.yaml','override.yaml'],rendered=rendered,service={'id':'demo','version':'1'},images=[])
        archive.writestr('manifest.json',json.dumps({'schema_version':'cats.remediation/v1','deployment_manifest':manifest}))
    digest=file_digest(path)
    assert validate_bundle(path,expected_type='standard-bundle',expected_digest=digest)==manifest
    assert manifest['deployment']['valuesFiles']==['candidate/values.yaml','candidate/override.yaml']
    assert 'documentation/remediation/summary.json' in manifest['files']
    with ZipFile(path,'a') as archive: archive.writestr('extra.yaml','unsafe: true')
    for expected in (None,digest):
        with pytest.raises(ValueError): validate_bundle(path,expected_digest=expected)

def result_for(request,status='VERIFIED',cleanup='COMPLETE'):
    return {'request_id':request['request_id'],'validation_type':request['validation_type'],'artifact_digest':request['artifact']['digest'],'service':request['service'],'status':status,'validation_id':'2'*32,'validator_id':'managed','cleanup_status':cleanup,'helm_result':{'install':'PASS','execution_mode':'HELM','release_status':'DEPLOYED','helm_release_verified':True}}

@pytest.mark.parametrize('field',['request_id','service','artifact_digest','validation_type','cleanup_status','helm_result'])
def test_success_rejects_swapped_binding_or_missing_deployment_proof(field):
    request={'request_id':'1'*32,'validation_type':'standard-bundle','service':{'id':'demo','version':'1'},'artifact':{'digest':'sha256:'+'a'*64}}
    result=result_for(request); result[field]={} if field=='helm_result' else 'wrong'
    with pytest.raises(ValueError): validation_result(result,request)

@pytest.mark.parametrize('static,status,expected',[('PASS','VERIFIED','verified'),('WARNING_UNVERIFIED','VERIFIED','verified'),('WARNING_UNVERIFIED','FAILED','failed')])
def test_runtime_exact_candidate_independent_states(workflow,monkeypatch,static,status,expected):
    db,_,_,_,_,root=workflow; row=candidate(workflow)
    row.validation_results={'checks':{'intended_changes':{'status':static}}}; row.delivery_status='download_ready'; row.signing_status='signed'; db.commit()
    monkeypatch.setattr(deployment_bundle,'validate_bundle',lambda path,**kw:{'service':{'id':'demo','version':'1'},'deployment':{'namespace':'cats-validation'}})
    selection=[]; calls=[]
    monkeypatch.setattr(main.validator_management,'select_configuration',lambda db,manual,kind:selection.append(kind) or {'endpoint':'https://managed','expected_validator_id':'managed'})
    def validate(configuration,request,*,artifact_path,progress_callback,state_callback):
        calls.append((request,artifact_path,artifact_path.read_bytes())); progress_callback('HELM_INSTALL')
        state_callback({'status':'RUNNING','validation_id':'2'*32,'validator_id':'managed','phase':'HELM_INSTALL'})
        return result_for(request,status)
    monkeypatch.setattr(validator_client,'validate',validate)
    main._validate_retained_remediation(db,row)
    assert selection==['standard-bundle'] and calls[0][2]==b'retained content'
    assert calls[0][1]==root/'R1'/'candidate.zip' and calls[0][0]['artifact']=={'reference':'R1','digest':row.artifact_digest}
    assert row.verification_status==expected, row.validation_results['deployment']
    assert row.remediation_status=='partial'
    assert row.delivery_status=='download_ready' and row.signing_status=='signed'
    assert row.validation_results['status']==static and len(row.validation_results['runtime_attempts'])==1

def test_blocker_does_not_contact_validator(workflow,monkeypatch):
    db,*_=workflow; row=candidate(workflow); row.validation_results={'checks':{'change_scope':{'status':'FAIL'}}}; db.commit()
    monkeypatch.setattr(main.validator_management,'select_configuration',lambda *_:pytest.fail('Blocked candidate selected validator'))
    main._validate_retained_remediation(db,row)
    assert row.verification_status=='blocked' and row.remediation_status=='partial'

def test_no_validator_is_distinct_unavailable(workflow,monkeypatch):
    db,*_=workflow; row=candidate(workflow)
    monkeypatch.setattr(deployment_bundle,'validate_bundle',lambda *a,**kw:{})
    monkeypatch.setattr(main.validator_management,'select_configuration',lambda *_:{})
    monkeypatch.setattr(validator_client,'validate',lambda *_:pytest.fail('Unavailable validator invoked'))
    main._validate_retained_remediation(db,row)
    assert row.verification_status=='unavailable' and row.remediation_status=='partial'
    assert 'healthy compatible' in row.validation_results['deployment']['detail']

def test_retry_same_candidate_background_without_new_remediation(workflow):
    db,service,_,auth,submitted,_=workflow; row=candidate(workflow); digest=row.artifact_digest
    assert main.validate_remediation_candidate(service.service_key,row.job_key,'token',db,auth).status_code==303
    assert submitted==[(main._run_retained_remediation_validation,row.id)] and row.artifact_digest==digest
    assert db.scalar(select(func.count(RemediationExecution.id)))==1
    with pytest.raises(HTTPException) as error: main.validate_remediation_candidate(service.service_key,row.job_key,'token',db,auth)
    assert error.value.status_code==409

@pytest.mark.parametrize('failure',['blocking','tamper','cleanup'])
def test_retry_rejects_unsafe_candidate(workflow,failure):
    db,service,_,auth,submitted,root=workflow; row=candidate(workflow)
    if failure=='blocking': row.validation_results={'status':'BLOCKING'}
    if failure=='tamper': (root/'R1'/'candidate.zip').write_bytes(b'tampered')
    if failure=='cleanup': row.validation_results={'deployment':{'cleanup_status':'UNKNOWN'}}
    db.commit()
    with pytest.raises(HTTPException) as error: main.validate_remediation_candidate(service.service_key,row.job_key,'token',db,auth)
    assert error.value.status_code==409 and not submitted

def test_resume_job_polls_without_duplicate_upload(monkeypatch):
    from test_validator_v2_transport import declaration
    request=declaration('oci'); job='2'*32; identity=validator_api._request_identity(request)
    result={**identity,'validation_id':job,'status':'FAILED','cleanup_status':'COMPLETE'}
    state={**identity,'validation_id':job,'status':'FAILED','phase':'COMPLETE','result':result}
    calls=[]; states=[]
    monkeypatch.setattr(validator_client,'_client_context',lambda *_:object())
    monkeypatch.setattr(validator_client,'_request',lambda url,*a,**kw:calls.append(url) or state)
    assert validator_client.validate({'endpoint':'https://managed'},request,resume_validation_id=job,state_callback=states.append)==result
    assert calls==['https://managed/api/v2/validations/'+job] and states==[state]
