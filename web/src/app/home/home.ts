import { Component } from '@angular/core';

/** Temporary landing page until the application shell lands (milestone M11). */
@Component({
  selector: 'app-home',
  template: `
    <main class="home">
      <h1>Central</h1>
      <p>Fleet management control plane.</p>
    </main>
  `,
  styles: `
    .home {
      display: grid;
      place-content: center;
      min-height: 100%;
      text-align: center;
    }
    h1 {
      font: var(--mat-sys-display-small);
      margin: 0;
    }
    p {
      color: var(--mat-sys-on-surface-variant);
    }
  `,
})
export class Home {}
