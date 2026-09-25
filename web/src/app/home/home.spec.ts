import { TestBed } from '@angular/core/testing';

import { Home } from './home';

describe('Home', () => {
  it('renders the product name', async () => {
    const fixture = TestBed.createComponent(Home);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('h1')?.textContent).toContain('Central');
  });
});
