import {render,screen,fireEvent,cleanup} from '@testing-library/react';
import {afterEach,it,expect} from 'vitest';
import {Page} from './service_definitions';
afterEach(cleanup);
it('retains multipart preview, scoped processing and component filters',()=>{
 const components=[{logical_name:'Good',source_type:'helm',status:'complete',scan_job_id:'abcdefgh123'},{logical_name:'Bad',source_type:'oci',status:'acquisition_failed',reason:'Unavailable'}];
 const {container}=render(<Page data={{csrf_token:'csrf',service:{id:1,name:'Service',service_key:'key'},may_edit:true,preview:{adapter_label:'Singularity',counts:{declared:2},components},preview_filename:'test.yml',preview_token:'token',definitions:[{id:3,source_reference:'test.yml',revision_count:2,source_metadata:{adapter:'singularity',counts:{declared:2},components}}]}}/>);
 expect(container.querySelector('form')).toHaveAttribute('enctype','multipart/form-data');expect(screen.getByText('Retain and process all components').closest('form')).toHaveAttribute('action','/services/key/definitions/confirm/token');
 fireEvent.change(screen.getByLabelText('Filter'),{target:{value:'failed'}});
 const retained=screen.getByText('Reprocess retained original').closest('article')!;
 expect(retained.querySelectorAll('tbody tr')[0]).toHaveAttribute('hidden');expect(retained.querySelectorAll('tbody tr')[1]).not.toHaveAttribute('hidden');
 fireEvent.change(screen.getByLabelText('Search components'),{target:{value:'nothing'}});expect(retained.querySelectorAll('tbody tr')[1]).toHaveAttribute('hidden');expect(screen.getByText('Scan abcdefgh (rendered images)')).toHaveAttribute('href','/scan?job_id=abcdefgh123');
});
