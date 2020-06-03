<script>
	import { onMount } from 'svelte';
	import { goto } from '@sapper/app';
	import { loginModalStore, userUUID } from '../stores.js';
	import { setUserId, setUserToken, setLoginModal, makeAuthenticateCall, initialize, checkPassword, setRippleButtons, setLabels } from '../common.js';
	import Modal from '../components/Modal.svelte';

	let signupEnabled = false;
	let signupName = ''
	let signupEmail = ''
	let signupPassword = '';
	let signupCode = '';
	let validEmail = false;
	let urlParams;
	let invited = false;
	let passwordWarnText = "";
	let passwordCheckTimeout;

	$: {
		signupEmail = signupEmail.trim();
		if (/^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/.test(signupEmail)){
			validEmail = true;
		} else {
			validEmail = false;
		}
		if (invited){
			if (signupName && validEmail && signupPassword && signupCode){
				signupEnabled = true;
				setRippleButtons();
			} else {
				signupEnabled = false;
			}
		} else {
			if (validEmail && signupName) {
				signupEnabled = true;
			} else {
				signupEnabled = false;
			}
		}
		if (signupPassword != ''){
			clearTimeout(passwordCheckTimeout);
			passwordCheckTimeout = setTimeout(async () => {
				passwordWarnText = await checkPassword(signupPassword)
			}, 500);
		} else {
			passwordWarnText = "";
		}
	}
	async function invite(){
		event.preventDefault();
		var d = await makeAuthenticateCall('/invite', {
			email: signupEmail,
			name: signupName,
		});
		if (!d){
			alert('Could not get invite. Try again!');
			return;
		}
		if (d.success){
			invited = true;
			initialize();
		} else {
			console.log(d.message);
			if (d.message == 'UserExists'){
				if (d.signedUp){
					login();
					alert('You have already signed up!');
				} else {
					alert("Invite already requested for this email. Check your inbox!");
				}
			} else {
				alert('Could not get invite. Try again!');
			}
		}
	}

	async function signup(){
		if (!signupEnabled){
			return false;
		}
		event.preventDefault();
		var d = await makeAuthenticateCall('/signup', {
			name: signupName,
			email: signupEmail,
			inviteCode: signupCode,
			password: signupPassword
		}, 'Could not sign up. Try again!');
		if (!d){
			return;
		}
		if (d.activated || d.message == 'SignedUp'){
			d = await makeAuthenticateCall('/login', {
				email: signupEmail,
				password: signupPassword
			});
			if (d && d.success){
				setUserId(d.uuid);
				setUserToken(d["auth-token"]);
				localStorage.setItem('uuid', d.uuid);
				localStorage.setItem(d.uuid+'_token', d["auth-token"]);
				setLoginModal(false);
				try{
					FS.identify(d.uuid, {
						email: signupEmail,
					});
				}
				catch (e){
					//Fullstory may be blocked, respect the user's privacy..
				}
			} else {
				console.error(d);
				alert('Could not login. Try again!');
			}
			localStorage.removeItem('signupName');
			localStorage.removeItem('signupEmail');
			localStorage.removeItem('signupCode');
			goto('/corporate');
		} else{
			console.error(d);
			let msg;
			switch (d.message){
				case 'InvalidEmailForInvite':
					msg = 'You need to use the same email as your invitation.';
				break;
				case 'InvalidInvite':
					msg = 'Your invitation code is not valid.';
				break;
				case 'ExpiredInvite':
					msg = 'Your invitation code has expired.';
				break;
				default:
					msg = 'Could not sign up. Try again!';
				break;
			}
			alert(msg);
		}
	}
	function login(){
		goto('/');
	}
	onMount(() => {
		urlParams = new URLSearchParams(window.location.search);
		signupName = urlParams.get('name') || localStorage.getItem('signupName') || '';
		if (urlParams.get('signupEmail')){
			signupEmail = urlParams.get('signupEmail').replace(' ', '+');
		} else {
			signupEmail = localStorage.getItem('signupEmail') || '';
		}
		signupCode = urlParams.get('inviteCode') || '';
		if (urlParams.get('inviteCode')){
			invited = true;
		}
		initialize();
		localStorage.setItem('signupName', signupName);
		localStorage.setItem('signupEmail', signupEmail);
		localStorage.setItem('signupCode', signupCode);
	});
</script>
<svelte:head>
	<title>Signup </title>
</svelte:head>
<div id="signuptab" class="col s12">
	<h4>Signup</h4>
	<form>
	<div class="row">
		<div class="input-field col s12">
			{#if invited}
			<input id="signupEmail" bind:value={signupEmail} type="email" class="validate" disabled>
			<label for="signupEmail">Your Email</label>
			<span class="helper-text">Email is tied to your invite</span>
			{:else}
			<input id="signupEmail" bind:value={signupEmail} type="email" class="validate" required>
			<label for="signupEmail">Email</label>
			<span class="helper-text">{#if signupEmail && !validEmail}Enter a valid email address{/if}</span>
			{/if}
		</div>
		<div class="input-field col s12">
			<input id="signupName" bind:value={signupName} type="text" class="validate" required>
			<label for="signupName">Your Name</label>
			<span class="helper-text">{signupName ? 'Hello '+signupName+'!' : ''}</span>
		</div>
		{#if invited}
		<div class="input-field col s12">
			<input id="signupPassword" bind:value={signupPassword} type="password" required>
			<label for="signupPassword">Password</label>
			{#if passwordWarnText}
			<span class="helper-text">{passwordWarnText}</span>
			{/if}
		</div>
		<div class="input-field col s12">
			<input id="signupCode" bind:value={signupCode} type="text" required>
			<label for="signupCode">Invitation Code</label>
			<span class="helper-text">{#if !signupCode}We emailed you an invite code{/if}</span>
		</div>
		{/if}
		{#if signupEnabled}
		<button class="mdc-button mdc-button--raised" on:click={invited ? signup : invite} type="submit">
			<span class="mdc-button__label">{invited ? 'Signup': 'Request Invite'}</span>
			<i class="material-icons mdc-button__icon right">send</i>
		</button>
		{:else}
		<button class="mdc-button mdc-button--raised" disabled type="submit">
			<span class="mdc-button__label">{invited ? 'Signup': 'Request Invite'}</span>
			<i class="material-icons mdc-button__icon right">send</i>
		</button>
		{/if}
		<button class="mdc-button right" on:click={login}>Existing User?</button>
	</div>
	</form>
</div>
