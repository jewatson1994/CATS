import {render, screen, fireEvent, cleanup, within} from '@testing-library/react';
import {afterEach, it, expect, vi} from 'vitest';
import {ServiceHeader} from './ServiceHeader';
afterEach(cleanup);
const data={view:{service:{id:7,service_key:'demo',name:'Demo Service'},version:'1.0'},can:{'service.delete':{'7':true}},csrf_token:'csrf'};
it('requires the exact service name phrase before enabling permanent deletion',()=>{
 HTMLDialogElement.prototype.showModal=vi.fn(function(this:HTMLDialogElement){this.setAttribute('open','');});
 render(<ServiceHeader data={data}/>);
 fireEvent.click(screen.getByRole('button',{name:'Delete service'}));
 const dialog=screen.getByRole('dialog',{name:'Permanently delete Demo Service'});
 const button=within(dialog).getByRole('button',{name:'Permanently delete service'});
 expect(button).toBeDisabled();
 const field=within(dialog).getByRole('textbox',{name:/Type delete Demo Service/});
 fireEvent.change(field,{target:{value:'delete demo'}});expect(button).toBeDisabled();
 fireEvent.change(field,{target:{value:'delete Demo Service'}});expect(button).toBeEnabled();
 expect(button.closest('form')).toHaveAttribute('action','/services/demo/delete');
});
it('does not offer deletion without permission',()=>{
 render(<ServiceHeader data={{...data,can:{}}}/>);
 expect(screen.queryByRole('button',{name:'Delete service'})).not.toBeInTheDocument();
});
