import {createContext, useContext} from 'react';

export const OperatingMode = createContext<'full' | 'replica'>('full');
export const useReplica = () => useContext(OperatingMode) === 'replica';
