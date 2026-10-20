import type {PageData} from '../api';
import {VexSettings} from './native_vex';
import {PolicyPage} from './policies';
export function Page({data}:{data:PageData}) {return <><PolicyPage data={data} kind="general"/><VexSettings data={data}/></>;}
