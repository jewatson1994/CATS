import type {PageData} from '../api';
import {VexSettings} from './native_vex';
import {PolicyPage} from './policies';
import {LogForwarding} from './log_forwarding';
export function Page({data}:{data:PageData}) {return <><PolicyPage data={data} kind="general"/><LogForwarding data={data}/><VexSettings data={data}/></>;}
