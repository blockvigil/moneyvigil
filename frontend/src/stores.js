import { writable } from 'svelte/store';

export const progressvar = writable(false);
export const loginModalStore = writable(false);
export const wsTxStore = writable('');
export const wxEventStore = writable('');
export const wsBillStore = writable('');

export const corporateProfileStore = writable(false);
export const userUUID = writable('');
export const userToken = writable('');
export const userCurrency = writable('');
