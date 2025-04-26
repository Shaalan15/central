import { Routes } from '@angular/router';
import { CentralComponent } from './central/central/central.component';

export const routes: Routes = [
    {
        path: '',
        component: CentralComponent,
    },
    // {
    //     path: 'home',
    //     loadChildren: () => import('./home/home.module').then(m => m.HomeModule)
    // },
    // {
    //     path: 'about',
    //     loadChildren: () => import('./about/about.module').then(m => m.AboutModule)
    // },
    {
        path: '**',
        redirectTo: ''
    }
];
