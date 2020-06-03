<script>
	import { onMount } from 'svelte';
	import { goto } from '@sapper/app';
	import { loginModalStore, userUUID } from '../stores.js';
	import { setUserId, setUserToken, setLoginModal, makeAuthenticateCall } from '../common.js';
	import Login from '../components/Login.svelte';

	let loginModal = false;
	const unsubscribeLGM = loginModalStore.subscribe(value => {
		loginModal = value;
	});
	let userUUID_value = '';
	const unsubscribeUID = userUUID.subscribe(value => {
		userUUID_value = value;
	});

	onMount(async () => {
		await logout();
		goto('/');
	});

	async function logout(){
		localStorage.removeItem('signupName');
		localStorage.removeItem('signupEmail');
		localStorage.removeItem('signupCode');
		var d = await makeAuthenticateCall('/logout', {});
		localStorage.removeItem('uuid');
		localStorage.removeItem(userUUID_value+'_token');
		setUserId('');
		setUserToken('');
		//setLoginModal(true);
	}
</script>
<svelte:head>
	<title>Logout </title>
</svelte:head>
{#if loginModal}
<Login loginText={"You are logged out!"} redirect={true}/>
{:else}
	<h3>Logging out...</h3>
{/if}
