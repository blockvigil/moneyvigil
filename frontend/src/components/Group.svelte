<script>
	import { createEventDispatcher, onMount, tick } from 'svelte';
	import { goto } from '@sapper/app';
	import { userUUID, userCurrency } from '../stores.js';
	import { currencyMap, makeAuthenticateCall, setRippleButtons, checkUser } from '../common.js';
	import Modal from './Modal.svelte';
	import Invite from './Invite.svelte';

	let groupEnabled = false;
	const dispatch = createEventDispatcher();

	let userUUID_value = '';
	const unsubscribeUID = userUUID.subscribe(value => {
		userUUID_value = value;
	});
	let userCurrency_value = '';
	const unsubscribeCur = userCurrency.subscribe(value => {
		userCurrency_value = value;
	});

	export let groupName = '';
	export let uuid = '';
	export let email = "";
	let prevEmail = "";
	let validEmail = false;
	let emailCheckTimeout;
	let isUser = {};
	let showInvite = false;
	let createEnabled = false;
	let currencyOptions = ["USD","INR","EUR","GBP","CNY"];
	let approvalEnabled = false;

	$: {
		email = email.trim();
		if (prevEmail != email){
			prevEmail = email;
			if (/^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/.test(email)){
				validEmail = true;
				isUser.checking = true;
				clearTimeout(emailCheckTimeout);
				emailCheckTimeout = setTimeout(async () => {
					isUser = await checkUser(email)
				}, 500);
			} else {
				validEmail = false;
				isUser = {};
			}
		}
		if (isUser.uuid && groupName){
			createEnabled = true;
			setRippleButtons();
			console.log('approvalEnabled', approvalEnabled);
		} else {
			createEnabled = false;
		}

	}

	async function addMember(){
		createEnabled = false;
		var d = await makeAuthenticateCall('/addmember', {
			"name": groupName,
			"member": isUser.uuid,
			"approval_required": approvalEnabled ? true: false,
			"group": uuid,
			"currency": uuid ? null : document.getElementById("currency").value
		});
		if (!d.success){
			alert('Could not add member');
			createEnabled = true;
			return;
		}
		M.toast({html: 'Added'+(uuid ? ' to ' : '')+' Group!'});
		dispatch("close", groupName);
		groupName = '';
		email = '';
	}

	onMount(async () => {
		for (let i in currencyMap){
			if (currencyOptions.indexOf(currencyMap[i]) == -1){
				currencyOptions = [...currencyOptions, currencyMap[i]];
			}
		}
		await tick();
		const elems = document.querySelectorAll('select');
		const instances = M.FormSelect.init(elems);
	});

</script>
{#if showInvite}
	<Invite inviteEmail={email} on:close="{() => {
		showInvite = false;
		(async () => {
			isUser = await checkUser(email);
			await tick();
			const elems = document.querySelectorAll('select');
			const instances = M.FormSelect.init(elems);
		})();
	}}" />
{:else}
<Modal disableOk={true} on:close="{() => dispatch("close")}">
	<h4>{uuid ? 'Add to': 'New'} Group</h4>
	<div class="row">
		{#if uuid}
		<div class="input-field col s12">
			<input id="group_name" type="text" class="validate" bind:value={groupName} disabled>
			<label for="group_name">Group's Name</label>
		</div>
		{:else}
		<div class="input-field col s9">
			<input id="group_name" type="text" class="validate" bind:value={groupName} required>
			<label for="group_name">Group's Name</label>
		</div>
		<div class="input-field col s6">
			<div class="switch">
				<label>
					Off
					<input type="checkbox" bind:checked={approvalEnabled}>
					<span class="lever"></span>
					On
				</label>
			</div>
		</div>
		<div class="input-field col s3">
			<select id="currency">
			{#each currencyOptions as currency}
				<option value={currency} selected={currency == userCurrency_value ? "selected": ""}>{currency}</option>
			{/each}
			</select>
			<label>Currency</label>
		</div>
		{/if}
		<div class="input-field col s12">
			<input id="group_member" type="email" name="email" class="validate" bind:value={email}>
			<label for="group_member">{#if isUser.name && isUser.uuid != userUUID_value}{isUser.name}{:else}Friend's Email{/if}</label>
			<span class="helper-text">
			{#if isUser.name}
				{#if isUser.uuid == userUUID_value}
				You are auto added. Enter a friend's email instead.
				{:else}
					{#if isUser.signedUp}
						Will add {isUser.name} to group. They will be able to see past bills.
					{:else}
						{isUser.name} hasn't signed up but can be added to group.
					{/if}
				{/if}
			{:else if validEmail}
				{#if isUser.checking}Checking..
				{:else}
				<button class="mdc-button mdc-button--raised" data-intercom-target="Show Invite" on:click="{() => showInvite = true}">Invite to BlockSplit</button>
				{/if}
			{:else if email}
				Enter a valid email address
			{/if}
			</span>
		</div>
	</div>
	<div slot="action" class="left">
		{#if createEnabled}
		<button class="mdc-button mdc-button--raised" type="submit" data-intercom-target="Create Group" on:click={addMember}>
			<span class="mdc-button__label">{#if uuid}Add {(isUser.name && isUser.uuid != userUUID_value) ? isUser.name : ''}{:else}Create Group{/if}</span>
			<i class="material-icons mdc-button__icon right">send</i>
		</button>
		{:else}
		<button class="mdc-button mdc-button--raised" type="submit" data-intercom-target="Create Group" on:click={addMember} disabled>
			<span class="mdc-button__label">{#if uuid}Add {(isUser.name && isUser.uuid != userUUID_value) ? isUser.name : ''}{:else}Create Group{/if}</span>
			<i class="material-icons mdc-button__icon right">send</i>
		</button>
		{/if}
	</div>
</Modal>
{/if}
