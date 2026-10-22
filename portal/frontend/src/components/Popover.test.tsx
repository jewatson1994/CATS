import {fireEvent, render, screen} from '@testing-library/react';
import {expect, it} from 'vitest';
import {Popover} from './Popover';

function Page() {
  return <main tabIndex={-1} data-testid="main"><button type="button">Elsewhere</button>
    <Popover label="Row density" button="Density">
      <fieldset><legend>Row density</legend><label><input type="radio" name="d" value="compact"/>Compact</label></fieldset>
    </Popover></main>;
}

it('stays open when pressing an option label moves focus to an ancestor such as <main>', () => {
  render(<Page/>);
  fireEvent.click(screen.getByRole('button', {name: 'Density'}));
  expect(screen.getByRole('dialog', {name: 'Row density'})).toBeInTheDocument();
  // Browsers focus the nearest focusable ancestor when non-focusable label text is pressed.
  fireEvent.pointerDown(screen.getByText('Compact'));
  fireEvent.focusIn(screen.getByTestId('main'));
  expect(screen.getByRole('dialog', {name: 'Row density'})).toBeInTheDocument();
  fireEvent.click(screen.getByLabelText('Compact'));
  expect(screen.getByLabelText('Compact')).toBeChecked();
});

it('still closes when focus or a pointer moves to something outside it', () => {
  render(<Page/>);
  fireEvent.click(screen.getByRole('button', {name: 'Density'}));
  fireEvent.focusIn(screen.getByRole('button', {name: 'Elsewhere'}));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', {name: 'Density'}));
  fireEvent.pointerDown(screen.getByRole('button', {name: 'Elsewhere'}));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});
