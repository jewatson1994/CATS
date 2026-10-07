import {createContext, useContext} from 'react';

export interface PageControl {
  /** Refetch the current page and replace its data in place if it changed. */
  refresh: () => Promise<void>;
}
export const PageControlContext = createContext<PageControl>({refresh: async () => {}});
/** Lets a page replace its own data in place (e.g. when preparation completes). */
export const usePageControl = () => useContext(PageControlContext);
