<script>
	import { onMount } from 'svelte';
	import { goto } from '@sapper/app';
	import { setUserId, setUserToken, setLoginModal, setRippleButtons, makeAuthenticateCall } from '../common.js';
	import Modal from './Modal.svelte';
	export let loginText = 'Not logged in!';
	export let redirect = false;
	let loginEmail = '';
	let loginPassword = '';
	let loginEnabled = false;
	let validEmail = false;
	$: {
		loginEmail = loginEmail.trim();
		if (/^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/.test(loginEmail)){
			validEmail = true;
		} else {
			validEmail = false;
		}
		if (validEmail && loginPassword){
			loginEnabled = true;
			setRippleButtons();
		} else {
			loginEnabled = false;
		}
	}

	onMount(() => {
		if (localStorage.getItem('signupCode')){
			signup();
		}
	});

	async function login(){
		if (!loginEnabled){
			return false;
		}
		event.preventDefault();
		var d = await makeAuthenticateCall('/login', {
			email: loginEmail,
			password: loginPassword
		});
		if (d.http_status && d.http_status != 401){
			console.log(d.http_status);
			alert('We are having trouble reaching our servers. Try again later!');
			return;
		}
		if (d.success){
			try{
				FS.identify(d.uuid, {
					email: loginEmail,
				});
			}
			catch (e){
				//Fullstory may be blocked, respect the user's privacy..
			}
			setUserId(d.uuid);
			setUserToken(d["auth-token"]);
			localStorage.setItem('uuid', d.uuid);
			localStorage.setItem(d.uuid+'_token', d["auth-token"]);
			localStorage.removeItem(d.uuid+'_info');
			setLoginModal(false);
			if (redirect){
				goto('/');
				//window.location.href = '/';
			} else {
				window.location.reload();
			}
		} else {
			if (d.message == 'NotActivated'){
				goto('/signup?activate='+loginEmail);
			} else{
				alert('Bad username or password. Try again!');
			}
		}
	}

	function signup(){
		goto('/signup');
	}
</script>
<Modal disableOk={true} disableCancel={true} alwaysShow={true} on:close="{() => { setLoginModal(true);}}">
	<h4>{loginText}</h4>
	<form>
	<div class="row">
		<div class="input-field col s12">
			<input id="loginEmail" bind:value={loginEmail} type="email" class="validate" required>
			<label for="loginEmail">Email</label>
			<span class="helper-text">{#if loginEmail && !validEmail}Enter a valid email address{/if}</span>
		</div>
		<div class="input-field col s12">
			<input id="loginPassword" bind:value={loginPassword} type="password" required>
			<label for="loginPassword">password</label>
		</div>
	</div>
	<div class="row">
		{#if loginEnabled}
		<button class="mdc-button mdc-button--raised" on:click={login} type="submit">
			<span class="mdc-button__label">Login</span>
			<i class="material-icons mdc-button__icon right">send</i>
		</button>
		{:else}
		<button class="mdc-button mdc-button--raised" disabled on:click={login} type="submit">
			<span class="mdc-button__label">Login</span>
			<i class="material-icons mdc-button__icon right">send</i>
		</button>
		{/if}
		<button type="button" class="mdc-button mdc-button--outlined right" on:click={signup}> New Account
		</button>
	</div>
	</form>
	<div class="row">
	</div>
</Modal>
