import js from '@eslint/js';
import ts from 'typescript-eslint';
import hooks from 'eslint-plugin-react-hooks';

export default ts.config(
  {ignores: ['node_modules/**']},
  js.configs.recommended,
  ...ts.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}', 'vite.config.ts'],
    languageOptions: {globals: {window:'readonly',document:'readonly',URL:'readonly',Headers:'readonly',Response:'readonly',
      FormData:'readonly',AbortController:'readonly',AbortSignal:'readonly',HTMLDialogElement:'readonly',HTMLInputElement:'readonly',
      HTMLFormElement:'readonly',HTMLElement:'readonly',SVGSVGElement:'readonly',ResizeObserver:'readonly',MouseEvent:'readonly',
      RequestInit:'readonly',fetch:'readonly',setTimeout:'readonly',clearTimeout:'readonly',setInterval:'readonly',clearInterval:'readonly',console:'readonly'}},
    plugins: {'react-hooks':hooks},
    rules: {
      'react-hooks/rules-of-hooks':'error',
      'react-hooks/exhaustive-deps':'warn',
      // Each page receives an explicit server DTO. Incremental per-page interface tightening is separate from the runtime boundary.
      '@typescript-eslint/no-explicit-any':'off',
      '@typescript-eslint/no-unused-vars':['error',{argsIgnorePattern:'^_',varsIgnorePattern:'^_'}],
      'no-restricted-syntax':['error',{selector:"JSXAttribute[name.name='dangerouslySetInnerHTML']",message:'Render text or native components; do not inject server HTML.'}],
    },
  },
);
