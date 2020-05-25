<script>
	import { onMount } from 'svelte';
	import { goto } from '@sapper/app';
	import { loginModalStore, userUUID, userCurrency, wsBillStore } from '../../stores.js';
	import { isLoggedIn, checkUser, makeAuthenticateCall, initWS, initialize, getFormattedMoney, checkMetaMask, signMessage, setToolTips } from '../../common.js';
	import Modal from '../../components/Modal.svelte';
	import Login from '../../components/Login.svelte';

	let showSettleModal = false;
	let loginModal = false;
	let showGroups = true;
	let localGroups = [];
	let bills = [];
	let billIndexes = [];
	let groups = [];
	let groupIndexes = [];
	let submitting = false;

	const unsubscribeLGM = loginModalStore.subscribe(value => {
		loginModal = value;
	});
	let userUUID_value = '';
	const unsubscribeUID = userUUID.subscribe(value => {
		userUUID_value = value;
	});
	let userCurrency_value = '';
	const unsubscribeCur = userCurrency.subscribe(value => {
		userCurrency_value = value;
	});

	const unsubscribeWBL = wsBillStore.subscribe(value => {
		if (value.confirmed){
			getGroups(null);
			showGroups = false;
		}
		if (bills.length > 0 && value && value.hash){
			const billIndex = billIndexes.indexOf(value.hash);
			if (billIndex != -1){
				if (value.state == 'BillSubmitted'){
					bills = bills.filter(b => b.uuidHash != value.hash);
					billIndexes = billIndexes.filter(b => b != value.hash);
					getGroups(null);
				}
			} else{
				//Probably got someone else's hash
				//console.error('got bad hash', value);
			}
			if (billIndexes.length == 0){
				M.toast({html: 'All payments confirmed on Blockchain!'});
			}
		}
	});

	onMount(async () => {
		if (isLoggedIn()){
			getGroups();
		}
		await initialize();
		const elems = document.querySelectorAll('select');
		const instances = M.FormSelect.init(elems);
	});
	let settlementPreview = {}
	let showGroupModal = false;

	async function getGroups(fetched){
		showGroups = false;
		showSettleModal = false;
		var d;
		if (fetched !== undefined){
			if (fetched){
				d = fetched;
			}
		} else {
			localGroups = JSON.parse(localStorage.getItem(userUUID_value+'_corporate_groups'));
			d = localGroups;
		}
		if (d){
			groups = d.data;
			groupIndexes = [];
			for (let j=0; j<groups.length; j++){
				let groupData = groups[j].groups;
				for (let i=0; i<groupData.length; i++){
					groupIndexes.push(groupData[i].uuid);
				}
			}
		}
		if (!fetched){
			d = await makeAuthenticateCall('/user/groups');
			if (d.success){
				localGroups = [];
				await getGroups(d);
				localStorage.setItem(userUUID_value+'_corporate_groups', JSON.stringify(d));
			} else {
				if (localGroups && localGroups.data.length > 0){
					showGroups = true;
				}
				localGroups = [""];
			}
		} else {
			showGroups = true;
			setToolTips();
		}
	}

</script>

<svelte:head>

	<title>Expense Groups </title>
</svelte:head>
{#if loginModal}
	<Login/>
{/if}
<div id="grouptab" class="col s12">
	<h3>Expense Groups</h3>
	{#if showSettleModal}
	<Modal on:close="{() => showSettleModal = false}" disableOk={true}>
		<ul class="collection">
		{#each settlementPreview.members.owes as item}
		<li class="collection-item">
			You owe {item.member.name} {getFormattedMoney(item.amount/100, settlementPreview.currency)}
			<div class="row">
				{#if item.pendingPayment}
					<button class="mdc-button mdc-button--raised" disabled>Pending Payment</button>
				{:else}
					<button class="mdc-button mdc-button--raised" on:click={(event) => {payCheck(event, item)}}>
						<span class="mdc-button__label loading">{#if submitting}Submitting<span>.</span><span>.</span><span>.</span>{:else}Mark as Paid{/if}</span>
					</button>
				{/if}
			</div>
		</li>
		{/each}
		{#each settlementPreview.members.owed as item}
		<li class="collection-item">{item.member.name} owes you {getFormattedMoney(item.amount/100, settlementPreview.currency)}</li>
		{/each}
		</ul>
	</Modal>
	{/if}
	<div class="row">
	{#if showGroups && localGroups.length > 0}
		<span class="helper-text red-text">Using offline data for groups</span>
	{/if}
	{#if showGroups}
		{#if groups.length > 0}
		<table id="groups" class="striped">
			<thead>
				<tr>
					<th>Name</th><th>Debt</th><th>Details</th>
				</tr>
			</thead>
			<tbody>
				{#each groups as groupData}
					{#each groupData.groups as group}
						<tr>
						<td on:click={() => {goto('/expenses/'+group.uuid+'_'+groupData.entityUUID)}}>{group.name}</td>
						<td>
						{#if group.totalOwes-group.totalOwed > 0}
							<button class="mdc-button" disabled>{getFormattedMoney((group.totalOwes-group.totalOwed)/100, group.currency)} Credit</button>
						{:else if group.totalOwes-group.totalOwed < 0}
							{#if group.members.filter((member) => !member.corporate_representation)[0].uuid == $userUUID}
								<button class="mdc-button mdc-button--raised" on:click={() => {goto('/expenses/'+group.uuid+'_'+groupData.entityUUID)}}>{getFormattedMoney((group.totalOwed-group.totalOwes)/100, group.currency)} - Owed</button>
							{:else}
								<button class="mdc-button" disabled>{getFormattedMoney((group.totalOwed-group.totalOwes)/100, group.currency)} - Owed</button>
							{/if}
						{:else}
							<button class="mdc-button" disabled>All Settled</button>
						{/if}
						{#if group.pendingBills > 0}
						<button class="mdc-button mdc-icon-button">
							<i class="material-icons tooltipped" data-position="top" data-tooltip={group.pendingBills>1 ? group.pendingBills+" Bills are pending on Blockchain" : group.pendingBills+" Bill is pending on Blockchain"}>sync</i>
						</button>
						{/if}
						</td>
						<td><button class="mdc-button mdc-button--dense mdc-button--outlined" on:click={() => {goto('/expenses/'+group.uuid+'_'+groupData.entityUUID)}}>Details</button></td></tr>
					{/each}
				{/each}
			</tbody>
		</table>
		{:else}
			We will show group details once you have been added to an expense group.
		{/if}
	{:else if localGroups && localGroups.length > 0}
		We could not fetch groups. Try again later.
	{:else}
		Fetching groups..
	{/if}
	</div>
</div>
