import {render,screen,fireEvent,cleanup} from '@testing-library/react';
import {afterEach,describe,it,expect} from 'vitest';
import {Page} from './exchange';
afterEach(cleanup);
const template={name:'PPSM',dataset:'ppsm',enabled:true,metadata:[],columns:[{field:'port',label:'Port'}],layout:{sheet:'PPSM'}};
describe('native exchange workflows',()=>{
  it('duplicates built-ins, resets dataset columns and sends explicit designer JSON',()=>{
    const {container}=render(<Page data={{csrf_token:'csrf',may_manage_templates:true,template_catalog:{ppsm:template,poam:{...template,name:'POAM',dataset:'poam',columns:[{field:'title',label:'Title'}]},assets:{...template,dataset:'assets'}},field_catalog:{metadata:{owner:'Owner'},datasets:{ppsm:{port:'Port'},poam:{title:'Title'},assets:{asset:'Asset'}}}}}/>);
    expect(screen.getByLabelText('Name')).toBeDisabled();
    fireEvent.click(screen.getByText('Duplicate selected template'));
    expect(screen.getByLabelText('Name')).toHaveValue('PPSM (copy)');
    fireEvent.change(screen.getByLabelText('Dataset'),{target:{value:'poam'}});
    fireEvent.click(screen.getByText('Add column'));
    let payload=JSON.parse((container.querySelector('[name=definition]') as HTMLInputElement).value);
    expect(payload.columns).toHaveLength(2);expect(payload.columns[0].field).toBe('title');expect(payload).not.toHaveProperty('isNew');
    fireEvent.click(screen.getByText('Reset changes'));
    payload=JSON.parse((container.querySelector('[name=definition]') as HTMLInputElement).value);
    expect(payload.dataset).toBe('ppsm');expect(container.querySelector('[name=template_id]')).toHaveValue('');
  });
  it('keeps version, CSRF, editable metadata and missing export acknowledgement',()=>{
    const {container}=render(<Page data={{csrf_token:'csrf',service:{id:1,name:'Service',service_key:'key'},version:'v1',versions:['v1','v2'],selected_template:'ppsm',catalog:{ppsm:{name:'PPSM',enabled:true}},definition:{...template,block_missing:true},may_import:true,may_export:true,may_edit_metadata:true,metadata:{'system.owner':'Old'},metadata_groups:{System:[{key:'system.owner',label:'Owner'}]},missing:['Port']}}/>);
    fireEvent.change(screen.getByLabelText('Owner'),{target:{value:'New'}});
    expect(JSON.parse((container.querySelector('[name=values]') as HTMLInputElement).value)).toEqual({'system.owner':'New'});
    expect(screen.getByText('Download PPSM')).toBeDisabled();expect(screen.getByLabelText('I reviewed the missing fields')).toBeRequired();
    const upload=container.querySelector('form[enctype="multipart/form-data"]')!;
    expect(upload).toHaveAttribute('action','/services/key/exchange/ppsm/preview');expect(upload.querySelector('[name=version]')).toHaveValue('v1');expect(upload.querySelector('[name=csrf_token]')).toHaveValue('csrf');
  });
  it('requires explicit conflict handling and blocks erroneous previews',()=>{
    const data={service:{id:1,name:'Service',service_key:'key'},version:'v1',token:'token',preview:{recognized:1,worksheet:'Sheet',header_row:2,new:0,conflicts:['x'],mapped:['Port'],ignored:[],errors:[],rows:[]}};
    const {rerender,container}=render(<Page data={data}/>);
    expect(screen.getByLabelText('Existing records')).toBeRequired();expect(container.querySelector('form')).toHaveAttribute('action','/services/key/exchange/confirm/token');
    rerender(<Page data={{...data,preview:{...data.preview,errors:['Invalid port']}}}/>);
    expect(screen.getByRole('alert')).toHaveTextContent('Invalid port');expect(screen.queryByLabelText('Existing records')).not.toBeInTheDocument();
  });
  it('validates portable bundles and requires acknowledgement before confirmation',()=>{
    const {rerender,container}=render(<Page data={{bundle_mode:true,csrf_token:'csrf'}}/>);
    expect(screen.getByLabelText('Service bundle')).toBeRequired();expect(container.querySelector('form')).toHaveAttribute('enctype','multipart/form-data');
    rerender(<Page data={{bundle_mode:true,csrf_token:'csrf',token:'token',target_key:'new',import_mode:'add_history',bundle_manifest:{format:'cats'},history_counts:{new:2,duplicates:1}}}/>);
    expect(screen.getByRole('checkbox')).toBeRequired();expect(container.querySelector('form')).toHaveAttribute('action','/exchange/bundles/confirm/token');expect(screen.getByText(/2 missing historical/)).toBeInTheDocument();
  });
});
