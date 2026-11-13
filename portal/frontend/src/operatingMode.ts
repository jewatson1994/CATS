import {createContext, useContext} from 'react';

export const OperatingMode = createContext<'full' | 'replica'>('full');
export const useReplica = () => useContext(OperatingMode) === 'replica';
// Imported service evidence remains read-only even in a full CATS deployment.
export const ServiceReadOnly = createContext(false);
export const useServiceReadOnly = (readOnly = false) => {
  const imported = useContext(ServiceReadOnly), replica = useReplica();
  return readOnly || imported || replica;
};
