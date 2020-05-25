<script>
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '@sapper/app';
	import { loginModalStore, wxEventStore, userUUID } from '../../stores.js';
	import { setUserId, setUserToken, setLoginModal, makeAuthenticateCall, initialize, checkPassword, setRippleButtons, checkMetaMask, initWS, setLabels } from '../../common.js';
	import Modal from '../../components/Modal.svelte';

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
	let companyDomain = "";
	let entity = {};
	let steps = [
		{
			name: 'Deploying ACL Contract',
			status: 0
		},
		{
			name: 'Adding Self as Owner',
			status: 0
		},
		{
			name: 'Adding Self as Employee',
			status: 0
		},
	];
	let stepIndexes = ['ACLDeployed', 'GlobalOwnerAdded', 'EmployeeAdded']
	let manageButton = false;
	let account = '';

	const unsubscribeWEVT = wxEventStore.subscribe(value => {
		if (value){
			if (value.data.companyUUIDHash == entity.uuidHash){
				console.log('event is for current company');
				let pos = stepIndexes.indexOf(value.name);
				if (pos != -1){
					console.log('updated status for', value.name);
					steps[pos].status = 1;
					if (steps.filter((step) => step.status == 0).length == 0){
						manageButton = true;
					}
				}
			}
		}
	});

	$: {
		signupEmail = signupEmail.trim();
		if (/^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/.test(signupEmail)){
			validEmail = true;
			companyDomain = signupEmail.split('@')[1];
		} else {
			validEmail = false;
		}
		if (signupName && validEmail){
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
		signupEnabled = false;
		var d = await makeAuthenticateCall('/corporateEntity/', {
			name: signupName,
			email: signupEmail,
			//inviteCode: signupCode,
			walletAddress: account,
			chainId: 5,
			deploy: true
		}, 'Could not sign up. Try again!');
		signupEnabled = true;
		if (!d){
			return;
		}
		initWS();
		console.log(d);
		if (d.entity){
			entity = d.entity;
		}
	}

	onMount(async () => {
		initialize();
		account = await checkMetaMask(true);
		if (account){
			console.log(account);
			var user = await makeAuthenticateCall('/user/');
			user = user.user;
			if (user.wallets.map((d) => d.address).indexOf(account) == -1){
				alert('You need to link this wallet first!');
				goto('/settings');
				return;
			}
		} else {
			console.error('metamask');
			alert('We need to allow Metamask/Portis.');
			return;
		}
	});

	onDestroy(() => {
		unsubscribeWEVT();
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
	<title>Corporate Signup </title>
</svelte:head>
<div id="signuptab" class="col s12">
	{#if !entity.name}
	<form>
	<h4>Corporate Signup</h4>
	<div class="row">
		<div class="input-field col s12">
			<input id="signupName" bind:value={signupName} type="text" name="company" class="validate" required>
			<label for="signupName">Your Company Name</label>
			<span class="helper-text">{signupName ? 'All aboard, '+signupName+'!' : ''}</span>
		</div>
		<div class="input-field col s12">
			{#if invited}
			<input id="signupEmail" bind:value={signupEmail} type="email" class="validate" disabled>
			<label for="signupEmail">Your Corporate Email</label>
			<span class="helper-text">Email is tied to your invite</span>
			{:else}
			<input id="signupEmail" bind:value={signupEmail} type="email" class="validate" required>
			<label for="signupEmail">Your Corporate Email</label>
			<span class="helper-text">{#if signupEmail && !validEmail}Enter a valid email address{:else if signupEmail}We will use {companyDomain} for recognizing employees.{/if}</span>
			{/if}
		</div>
		<!--
		<div class="input-field col s12">
			<input id="signupCode" bind:value={signupCode} type="text" required>
			<label for="signupCode">Invitation Code</label>
		</div>
		-->
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
	</div>
	</form>
	{:else}
	<h4>Creating Entity - {entity.name}</h4>
	<div class="row">
		<table id="groups" class="striped">
			<thead>
				<tr>
					<th>Action</th><th>Status</th>
				</tr>
			</thead>
			<tbody>
				{#each steps as step}
				<tr>
					<td>
						{step.name}
					</td>
					<td>
						{#if step.status == 0}
						<div class="preloader-wrapper small active">
							<div class="spinner-layer">
								<div class="circle-clipper left">
									<div class="circle"></div>
								</div><div class="gap-patch">
									<div class="circle"></div>
								</div><div class="circle-clipper right">
									<div class="circle"></div>
								</div>
							</div>
						</div>
						{:else}
						<button class="mdc-button mdc-button--dense mdc-button--outlined" disabled>Done</button>
						{/if}
					</td>
				</tr>
				{/each}
			</tbody>
		</table>
	</div>
		{#if manageButton}
		<div class="row">
			<button class="mdc-button mdc-button--raised" on:click={() => {goto('/corporate/'+entity.uuid)}}>Manage Entity</button>
		</div>
		{/if}
	{/if}
</div>
