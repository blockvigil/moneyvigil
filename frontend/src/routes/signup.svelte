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
	let signupToken = 0;
	let activateForm = false;
	let activeEnabled = false;
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
		if (signupName && validEmail && signupPassword && signupCode){
			signupEnabled = true;
			setRippleButtons();
		} else {
			signupEnabled = false;
		}
		signupToken = !signupToken || isNaN(signupToken) ? 0 : parseInt(signupToken);
		if (signupToken > 0 && signupEmail){
			activeEnabled = true;
			setRippleButtons();
		} else {
			activeEnabled = false;
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
		if ((d.success && !d.activated) || d.message == 'NotActivated' || d.message == 'ActivationExpired'){
			activateForm = true;
			await setLabels();
			M.updateTextFields();
			setRippleButtons();
		} else {
			if (d.activated || d.message == 'SignedUp'){
				activate(null, true);
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
	}
	onMount(() => {
		urlParams = new URLSearchParams(window.location.search);
		if (urlParams.get('activationEmail')){
			activateForm = true;
			signupEmail = urlParams.get('activationEmail') || '';
			signupToken = urlParams.get('activationCode') || 0;
		} else {
			signupName = urlParams.get('name') || localStorage.getItem('signupName') || '';
			if (urlParams.get('signupEmail')){
				signupEmail = urlParams.get('signupEmail').replace(' ', '+');
			} else {
				signupEmail = localStorage.getItem('signupEmail') || '';
			}
			signupCode = urlParams.get('inviteCode') || localStorage.getItem('signupCode') || '';
			if (urlParams.get('inviteCode')){
				invited = true;
			}
		}
		initialize();
		localStorage.setItem('signupName', signupName);
		localStorage.setItem('signupEmail', signupEmail);
		localStorage.setItem('signupCode', signupCode);
	});
	async function activate(event, login){
		var d;
		if (!login){
			if (!activeEnabled){
				return false;
			}
			if (event){
				event.preventDefault();
			}
			d = await makeAuthenticateCall('/activate', {
				token: signupToken.toString(),
				email: signupEmail
			}, 'Could not activate. Try again!');
			if (!d){
				return;
			}
		}
		if (login || d.success || d.message == 'SignedUp'){
			if (!urlParams.get('activationEmail')){
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
			}
			localStorage.removeItem('signupName');
			localStorage.removeItem('signupEmail');
			localStorage.removeItem('signupCode');
			goto('/?product_tour_id=31368');
		} else {
			if (d.message == 'ActivationExpired'){
				alert('We have sent you a new activation code!');
				signupToken = 0;
			} else {
				alert('Could not activate with the code. Try again!');
			}
		}
	}
	function login(){
		goto('/logout');
	}
</script>
<svelte:head>
	<title>Signup </title>
</svelte:head>
<div id="signuptab" class="col s12">
	<h4>Signup</h4>
	<form>
	{#if activateForm}
	<div class="row">
		<div class="input-field col s12">
			<input id="signupToken" bind:value={signupToken} type="text" class="validate" required>
			<label for="signupToken">Enter Activation Code</label>
			<span class="helper-text">{#if !signupToken}We emailed you a code{/if}</span>
		</div>
		<div class="input-field col s12">
			<input id="signupEmail" bind:value={signupEmail} type="email" disabled>
			<label for="signupEmail">Email</label>
		</div>
		{#if activeEnabled}
		<button class="mdc-button mdc-button--raised" on:click={activate} type="submit" onsubmit="return false">Finish Signup
			<i class="material-icons right">send</i>
		</button>
		{:else}
		<button class="mdc-button mdc-button--raised" disabled  on:click={activate}>Finish Signup
			<i class="material-icons right">send</i>
		</button>
		{/if}
	</div>
	{:else}
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
		</div>
		{#if signupEnabled}
		<button class="mdc-button mdc-button--raised" on:click={signup} type="submit">
			<span class="mdc-button__label">Signup</span>
			<i class="material-icons mdc-button__icon right">send</i>
		</button>
		{:else}
		<button class="mdc-button mdc-button--raised" disabled on:click={signup} type="submit">
			<span class="mdc-button__label">Signup</span>
			<i class="material-icons mdc-button__icon right">send</i>
		</button>
		{/if}
		<button class="mdc-button right" on:click={login}>Existing User?</button>
	</div>
	{/if}
	</form>
</div>
