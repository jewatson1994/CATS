import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {ServiceOCIDestinations} from './service-oci';
import {requestJson} from '../api';

vi.mock('../api',async importOriginal => ({...await importOriginal<any>(),requestJson:vi.fn()}));
afterEach(() => {cleanup();vi.clearAllMocks();});
const data = {service:{id:1,service_key:'one'},csrf_token:'csrf',can:{'service.edit':{'1':true}},oci_destinations:[{id:'1',scope:'service',name:'Private',endpoint:'https://registry.example',namespace:'team',credentials_configured:true,ca_configured:true}]};

it('limits destination configuration to service managers',() => {
  render(<ServiceOCIDestinations data={{...data,can:{}}}/>);
  expect(screen.queryByText('OCI destinations')).not.toBeInTheDocument();
});

it('rotates secrets without returning stored credentials',async () => {
  vi.mocked(requestJson).mockResolvedValueOnce({}).mockResolvedValueOnce(data.oci_destinations);
  render(<ServiceOCIDestinations data={data}/>);
  fireEvent.change(screen.getByLabelText('Destination'),{target:{value:'1'}});
  expect(screen.getByLabelText('Replacement password or token')).toHaveValue('');
  expect(screen.getByLabelText('Replacement username')).toHaveValue('');
  fireEvent.change(screen.getByLabelText('Replacement password or token'),{target:{value:'replacement'}});
  fireEvent.click(screen.getByText('Save destination'));
  await waitFor(() => expect(requestJson).toHaveBeenCalledTimes(2));
  const options = vi.mocked(requestJson).mock.calls[0][1]!;
  expect(options.headers).toMatchObject({'X-CSRF-Token':'csrf'});
  expect(JSON.parse(String(options.body))).toMatchObject({password:'replacement',endpoint:'https://registry.example'});
  expect(JSON.parse(String(options.body))).not.toHaveProperty('username');
});

it('shows limited connection capabilities accurately',async () => {
  vi.mocked(requestJson).mockResolvedValue({tls:'PASSED',push:'NOT TESTED',helm_oci:'NOT TESTED'});
  render(<ServiceOCIDestinations data={data}/>);
  fireEvent.change(screen.getByLabelText('Destination'),{target:{value:'1'}});
  fireEvent.click(screen.getByText('Test connection'));
  expect(await screen.findByText('push: NOT TESTED')).toBeInTheDocument();
  expect(screen.getByText('helm oci: NOT TESTED')).toBeInTheDocument();
});
