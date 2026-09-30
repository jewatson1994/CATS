import {render,screen,fireEvent,cleanup} from '@testing-library/react';
import {afterEach,it,expect} from 'vitest';
import {Page} from './purpose_export_template';
afterEach(cleanup);
it('preserves native repeated fields after reorder, heading reset and group inheritance',()=>{
 const {container}=render(<Page data={{csrf_token:'csrf',kind:'poam',name:'POAM',mode:'custom',source:'Group',group_id:2,columns:[{field:'a',heading:'Custom',enabled:true},{field:'b',heading:'B',enabled:false}],labels:{a:'Alpha',b:'Beta'},defaults:{a:'A',b:'B'}}}/>);
 fireEvent.click(screen.getByLabelText('Move Alpha down'));
 expect(Array.from(container.querySelectorAll('[name=field]')).map(input=>(input as HTMLInputElement).value)).toEqual(['b','a']);
 fireEvent.click(screen.getAllByText('Default heading')[1]);expect(screen.getByLabelText('Excel heading for Alpha')).toHaveValue('A');
 const form=container.querySelector('form')!;const payload=new FormData(form);expect(payload.getAll('field')).toEqual(['b','a']);expect(payload.getAll('heading')).toEqual(['B','A']);expect(payload.getAll('enabled')).toEqual(['a']);expect(payload.get('csrf_token')).toBe('csrf');
 expect(screen.getByText('Inherit parent')).toHaveAttribute('value','inherit');expect(form).toHaveAttribute('action','/admin/general-policy/export-templates/poam?group_id=2');
});
