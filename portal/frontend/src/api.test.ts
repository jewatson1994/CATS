import {afterEach,describe,expect,it,vi} from 'vitest';
import {requestJson,ApiError,PAGE_MEDIA_TYPE} from './api';
afterEach(()=>vi.unstubAllGlobals());
describe('same-origin API boundary',()=>{
  it('rejects external API destinations before sending cookies',async()=>{
    const fetch=vi.fn();vi.stubGlobal('fetch',fetch);
    await expect(requestJson('https://evil.invalid/')).rejects.toThrow('External API URLs');
    expect(fetch).not.toHaveBeenCalled();
  });
  it('keeps cookie credentials local and forwards CSRF multipart payloads',async()=>{
    const fetch=vi.fn().mockResolvedValue(new Response('{"ok":true}',{headers:{'content-type':PAGE_MEDIA_TYPE}}));vi.stubGlobal('fetch',fetch);
    const body=new FormData();body.set('csrf_token','proof');
    await expect(requestJson('/scan',{method:'POST',body,headers:{Accept:PAGE_MEDIA_TYPE}})).resolves.toEqual({ok:true});
    expect(fetch.mock.calls[0][1]).toMatchObject({credentials:'same-origin',cache:'no-store',body});
    expect(fetch.mock.calls[0][1].headers.get('Accept')).toBe(PAGE_MEDIA_TYPE);
    expect(fetch.mock.calls[0][1].headers.has('Content-Type')).toBe(false);
  });
  it('preserves server validation and refuses unexpected HTML',async()=>{
    const fetch=vi.fn().mockResolvedValueOnce(new Response('{"detail":"Forbidden"}',{status:403,headers:{'content-type':'application/json'}})).mockResolvedValueOnce(new Response('<html>login</html>',{headers:{'content-type':'text/html'}}));vi.stubGlobal('fetch',fetch);
    await expect(requestJson('/restricted')).rejects.toMatchObject({status:403,message:'Forbidden'});
    await expect(requestJson('/wrong')).rejects.toBeInstanceOf(ApiError);
  });
});
