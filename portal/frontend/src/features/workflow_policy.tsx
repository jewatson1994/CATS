import type {PageData} from '../api';
import {PolicyPage} from './policies';
export function Page({data}:{data:PageData}) {return <PolicyPage data={data} kind="workflow"/>;}
