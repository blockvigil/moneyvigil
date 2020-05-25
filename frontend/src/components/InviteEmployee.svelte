<script>
	import { createEventDispatcher, onMount } from 'svelte';
	import { goto } from '@sapper/app';
	import { setRippleButtons, makeAuthenticateCall } from '../common.js';
	import Modal from './Modal.svelte';
	export let inviteEmail;
	export let entity;
	export let inviteName = inviteEmail.split('@')[0];
	let inviteEnabled = false;
	const dispatch = createEventDispatcher();

	let prevEmail = "";
	let validEmail = false;
	let remainingInvites;

	$: {
		inviteEmail = inviteEmail.trim();
		if (prevEmail != inviteEmail){
			prevEmail = inviteEmail;
			if (/^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/.test(inviteEmail)){
				validEmail = true;
			} else {
				validEmail = false;
			}
		}
		if (validEmail && inviteName){
			inviteEnabled = true;
			setRippleButtons();
		} else {
			inviteEnabled = false;
		}
	}

	onMount(async () => {
		var d = await makeAuthenticateCall('/user/');
		if (!d || !d.success){
			return;
		}
		remainingInvites = d.user.remainingInvites;
	});

	async function invite(){
		inviteEnabled = false;
		var d = await makeAuthenticateCall('/corporateEntity/'+entity+'/users/', {
			employees: [{
				name: inviteName,
				email: inviteEmail
			}],
			entityUUID: entity
		});
		if (!d.success){
			inviteEnabled = true;
			if (d.message == "InviteExists"){
				M.toast({html: 'Employee has already been invited!'});
				dispatch("close");
				return;
			}
			alert('Could not invite. Try again!')
			return;
		}
		d = d.inviteStatus[0]
		if (d.invitedStatus){
			if (d.emailDeliveryStatus){
				M.toast({html: 'Invited employee!'});
			} else {
				M.toast({html: 'Invited employee! We will send an email shortly..'});
			}
		} else {
			M.toast({html: 'You are out of invites!'});
		}
		dispatch("close");
	}
</script>
<Modal disableOk={true} on:close="{() => dispatch("close")}">
	<h4>Invite Employee - {entity}</h4>
	<div class="row">
		<div class="input-field col s12">
			<input id="inviteName" bind:value={inviteName} type="text" class="validate" required>
			<label for="inviteName">Employee's Name</label>
		</div>
		<div class="input-field col s12">
			<input id="inviteEmail" type="email" name="email" class="validate" bind:value={inviteEmail}>
			<label for="inviteEmail">Email</label>
		<span class="helper-text">{#if !validEmail}Enter a valid email address{:else if remainingInvites > 0}You have {remainingInvites} invite{remainingInvites == 1 ? '': 's'} remaining.{:else}You are out of invites but you may still add your friend on bills. We will email them as we release more!{/if}</span>
		</div>
	</div>
	<div slot="action" class="left">
		{#if inviteEnabled}
		<button class="mdc-button mdc-button--raised" data-intercom-target="Send Invite" type="submit" on:click={invite}>
			<span class="mdc-button__label">Send Invite</span>
			<i class="material-icons mdc-button__icon right">send</i>
		</button>
		{:else}
		<button class="mdc-button mdc-button--raised" data-intercom-target="Send Invite" type="submit" on:click={invite} disabled>
			<span class="mdc-button__label">Send Invite</span>
			<i class="material-icons mdc-button__icon right">send</i>
		</button>
		{/if}
	</div>
</Modal>
