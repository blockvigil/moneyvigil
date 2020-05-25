<script>
	import { onMount } from 'svelte';
	import { loginModalStore, userUUID } from '../stores.js';
	import { isLoggedIn, makeAuthenticateCall, checkPassword, setRippleButtons, checkMetaMask, signMessage, personalSign, initialize } from '../common.js';
	import Login from '../components/Login.svelte';

	let loginModal = false;
	const unsubscribeLGM = loginModalStore.subscribe(value => {
		loginModal = value;
	});
	let userUUID_value = '';
	const unsubscribeUID = userUUID.subscribe(value => {
		userUUID_value = value;
	});

	let user = {};
	let invitesText;
	let currentPassword = "";
	let newPassword = "";
	let newPasswordRepeat = "";
	let passwordWarnText = "";
	let passwordCheckTimeout;
	let submitting = false;
	let saveEnabled = false;
	let prevName = ''
	let prevSubscription;
	let changePasswordEnabled = false;

	$: {
		if (newPassword != ''){
			clearTimeout(passwordCheckTimeout);
			passwordCheckTimeout = setTimeout(async () => {
				passwordWarnText = await checkPassword(newPassword)
			}, 500);
		} else {
			passwordWarnText = "";
		}
		if (prevName != '' && prevName != user.name){
			saveEnabled = true;
			setRippleButtons();
		}
		if (prevSubscription !== undefined && prevSubscription !== user.emailSubscription){
			saveEnabled = true;
			setRippleButtons();
		}
		if (user.uuid && user.name.trim() == ''){
			saveEnabled = false;
		}
		if ((currentPassword && newPassword && newPassword == newPasswordRepeat)){
			changePasswordEnabled = true;
			setRippleButtons();
		} else {
			changePasswordEnabled = false;
		}
	}

	onMount(async () => {
		if (isLoggedIn()){
			await getInfo();
		}
		initialize();
	});

	async function getInfo(){
		var d = await makeAuthenticateCall('/user/');
		if (!d.success){
			alert('Could not fetch info!');
			return;
		}
		user = d.user;
		prevName = user.name;
		prevSubscription = user.emailSubscription;
		invitesText = user.remainingInvites+'/'+(user.sentInvites+user.remainingInvites);
		user.ethAddress = await checkMetaMask(true);
		if (user.ethAddress.length){
			user.ethAddress = user.ethAddress.toLowerCase();
			console.log('address', user.ethAddress)
		} else {
			console.log('empty address?', user.ethAddress)
		}
		if (user.wallets.map((d) => d.address).indexOf(user.ethAddress) != -1){
			user.walletLinked = true;
			for (let i=0; i<user.connectedEntities.length; i++){
				user.connectedEntities[i].uniqueAddresses = (user.connectedEntities[i].roles.flatMap((d) => d.connectedAddresses)).filter((value, index, self) => self.indexOf(value) === index);
				console.log('got addresses', user.connectedEntities[i].roles, user.connectedEntities[i].uniqueAddresses);
				user.connectedEntities[i].linkedStatus = user.connectedEntities[i].uniqueAddresses.length == 0 ? 'Unlinked' :  (user.connectedEntities[i].uniqueAddresses.indexOf(user.ethAddress) != -1 ? 'Linked' : 'Different Address');
			}
		}
	}

	async function saveInfo(e){
		e.preventDefault();
		saveEnabled = false;
		submitting = true;
		var d = await makeAuthenticateCall('/user/', {
			name: user.name,
			email_subscription: user.emailSubscription ? true : false
		}, false, false, false, false, 'put');
		submitting = false;
		if (!d.success){
			alert('Could not update info!');
			saveEnabled = true;
			return;
		}
		prevName = user.name;
		prevSubscription = user.emailSubscription;
		M.toast({html: 'Saved!'});
	}

	async function linkWallet(e){
		e.preventDefault();
		e.target.parentElement.disabled = true;
		var data = {
			walletAddresses: [{
				name: "Wallet "+(user.wallets.length+1),
				address: user.ethAddress,
				msg: "Login with MoneyVigil",
				sig: await personalSign("Login with MoneyVigil")
			}]
		}
		var d = await makeAuthenticateCall('/user/', data, false, false, false, false, 'put');
		if (!d.success){
			alert('Could not link wallet!');
			e.target.parentElement.disabled = false;
			return;
		}
		getInfo();
		M.toast({html: 'Wallet Linked!'});
	}

	async function linkEntityWallet(e, uuid){
		e.preventDefault();
		e.target.parentElement.disabled = true;
		var data = {
			entityUUID: uuid,
			employees: [{
				uuid: user.uuid,
				eth_address: user.ethAddress
			}]
		}
		var d = await makeAuthenticateCall('/corporateEntity/'+uuid+'/users/', data, false, false, false, false, 'put');
		if (!d.success){
			alert('Could not link wallet!');
			e.target.parentElement.disabled = false;
			return;
		}
		getInfo();
		M.toast({html: 'Wallet Linked to Entity!'});
	}

	async function changePassword(e){
		e.preventDefault();
		changePasswordEnabled = false;
		submitting = true;
		var d = await makeAuthenticateCall('/user/', {
			password: {
				oldPassword: currentPassword,
				newPassword: newPassword
			}
		}, false, false, false, false, 'put');
		e.target.parentElement.disabled = false;
		submitting = false;
		if (!d.success){
			alert('Could not change password! Check your current password.');
			changePasswordEnabled = true;
			return;
		}
		currentPassword = ''
		newPassword = '';
		newPasswordRepeat = '';
		M.toast({html: 'New Password Set!'});
	}

	async function signedType3(event) {
	event.preventDefault()
	console.log(await checkMetaMask(true));
	const message = await signMessage();
	if (message.result){
		console.log('cool');
	}
}

</script>
<svelte:head>
	<title>Settings </title>
</svelte:head>
{#if loginModal}
	<Login/>
{/if}
<div id="settingstab" class="col s12">
	<h4>Settings</h4>
	{#if user.uuid}
	<form>
	<div class="row">
		<div class="input-field col s12">
			<input id="name" name="name" type="text" bind:value={user.name} class="validate" required>
			<label for="name">Your Name</label>
		</div>
		<div class="input-field col s6">
			Email Notifications
		</div>
		<div class="input-field col s6">
			<div class="switch">
				<label>
					Off
					<input type="checkbox" bind:checked={user.emailSubscription}>
					<span class="lever"></span>
					On
				</label>
			</div>
		</div>
	</div>
	<div class="row">
		<div class="input-field col s12">
		{#if saveEnabled}
			<button class="mdc-button mdc-button--raised" on:click={saveInfo} type="submit">
				<i class="material-icons mdc-button__icon">save</i>
				<span class="mdc-button__label">Save</span>
			</button>
		{:else}
		<button class="mdc-button mdc-button--raised" on:click={saveInfo} type="submit" disabled>
			<i class="material-icons mdc-button__icon">save</i>
			<span class="mdc-button__label loading">{#if submitting}Saving<span>.</span><span>.</span><span>.</span>{:else}Save{/if}</span>
		</button>
		{/if}
		</div>
	</div>
	</form>
	<form>
	{#if user.ethAddress}
		{#if user.walletLinked}
		<table class="striped">
			<thead>
				<tr>
					<th>Name</th><th>Linked Addresses</th><th>Status</th>
				</tr>
			</thead>
			<tbody>
			{#each user.connectedEntities as entity}
				<tr>
					<td>{entity.entity.name}</td>
					<td>{entity.uniqueAddresses}</td>
					<td>{#if entity.linkedStatus == 'Unlinked'}
					<button class="mdc-button mdc-button--raised" on:click={(event) => {linkEntityWallet(event, entity.entity.uuid)}}>
						<span class="mdc-button__label">Link Wallet</span>
						</button>
					{:else}
					{entity.linkedStatus}
					{/if}</td>
				</tr>
			{/each}
			</tbody>
		</table>
		{:else}
		<button class="mdc-button mdc-button--raised" on:click={linkWallet} type="submit">
			<i class="material-icons mdc-button__icon">link</i>
			<span class="mdc-button__label">Link Wallet</span>
		</button>
		{/if}
	{/if}
	<div class="row">
		<div class="input-field col s12">
			<input id="currentPassword" type="password" bind:value={currentPassword} required>
			<label for="currentPassword">Your Current password</label>
		</div>
		<div class="input-field col s12">
			<input id="newPassword" type="password" bind:value={newPassword} required>
			<label for="newPassword">New password</label>
			{#if passwordWarnText}
			<span class="helper-text">{passwordWarnText}</span>
			{/if}
		</div>
		<div class="input-field col s12">
			<input id="newPasswordRepeat" type="password" bind:value={newPasswordRepeat} class={newPasswordRepeat != '' ? (newPassword == newPasswordRepeat ? 'valid': 'invalid'): ''} required>
			<label for="newPasswordRepeat">Repeat</label>
			{#if newPasswordRepeat != '' && newPassword != newPasswordRepeat}
			<span class="helper-text red-text">Passwords do not match</span>
			{/if}
		</div>
		<div class="input-field col s12">
			{#if changePasswordEnabled}
			<button class="mdc-button mdc-button--raised" on:click={changePassword} type="submit">
				<i class="material-icons mdc-button__icon">vpn_key</i>
				<span class="mdc-button__label">Change Password</span>
			</button>
			{:else}
			<button class="mdc-button mdc-button--raised" type="submit" disabled>
				<i class="material-icons mdc-button__icon">vpn_key</i>
				<span class="mdc-button__label loading">{#if submitting}Changing<span>.</span><span>.</span><span>.</span>{:else}Change Password{/if}</span>
			</button>
			{/if}
		</div>
	</div>
	</form>
	<div class="row">
		<div class="input-field col s12">
			<input id="email" name="email" type="text" bind:value={user.email} required disabled>
			<label for="email">Your Email</label>
		</div>
		<div class="input-field col s12">
			<input id="invites" type="text" bind:value={invitesText} disabled>
			<label for="invites">Remaining Invites</label>
		</div>
	</div>
	{/if}
</div>
