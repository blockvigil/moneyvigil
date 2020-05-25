<script>
	import { onMount } from 'svelte';
	import { goto } from '@sapper/app';
	import { loginModalStore, userUUID, userCurrency, wsBillStore } from '../../stores.js';
	import { isLoggedIn, checkUser, makeAuthenticateCall, initWS, initialize, getFormattedMoney, checkMetaMask, signMessage, setToolTips } from '../../common.js';
	import Modal from '../../components/Modal.svelte';
	import Login from '../../components/Login.svelte';
	import Group from '../../components/Group.svelte';

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
			localGroups = JSON.parse(localStorage.getItem(userUUID_value+'_groups'));
			d = localGroups;
		}
		if (d){
			groups = d.groups;
			groupIndexes = [];
			for (let i=0; i<groups.length; i++){
				groupIndexes.push(groups[i].uuid);
			}
		}
		if (!fetched){
			d = await makeAuthenticateCall('/user/groups');
			if (d.success){
				localGroups = [];
				await getGroups(d);
				localStorage.setItem(userUUID_value+'_groups', JSON.stringify(d));
			} else {
				if (localGroups && localGroups.groups.length > 0){
					showGroups = true;
				}
				localGroups = [""];
			}
		} else {
			showGroups = true;
			setToolTips();
		}
	}

	async function payCheck (event, item) {
		event.target.parentElement.disabled = true;
		if (0 && await checkMetaMask()){
			if (await signMessage({
				type: "Settlement",
				amount: item.amount,
				group: settlementPreview.group,
				member: item.member.uuid
			})){
				showSettleModal = false;
			} else {
				event.target.parentElement.disabled = false;
			}
		} else {
			if (confirm('This will settle the debt. Are you sure?')){
				paySettle(event, settlementPreview.group, item.member.uuid, item.amount);
			} else {
				event.target.parentElement.disabled = false;
			}
		}
	}

	async function paySettle(e, group_uuid, member_uuid, totalAmount){
		//e.target.parentElement.disabled = true;
		submitting = true;
		let expenseMap = {};
		expenseMap[userUUID_value] = {
			paid: totalAmount,
			owes: 0
		}
		expenseMap[member_uuid] = {
			paid: 0,
			owes: totalAmount
		}
		var d = await makeAuthenticateCall('/addbill', {
			expenseMap: expenseMap,
			group: group_uuid,
			description: 'Payment settlement',
			date: (new Date()).toString(),
			totalAmount: totalAmount
		});
		if (!d.success){
			e.target.parentElement.disabled = false;
			alert('Could not add payment! Try again later.');
		}
		else {
			billIndexes = [...billIndexes, d.bill.uuidHash];
			bills = [...bills, d.bill];
			const groupIndex = groupIndexes.indexOf(group_uuid);
			if (!groups[groupIndex].pendingPayment){
				groups[groupIndex].pendingPayment = [];
			}
			groups[groupIndex].pendingPayment = [...groups[groupIndex].pendingPayment, member_uuid];
			groups[groupIndex].pendingBills++;
			initWS();
			M.toast({html: 'Added Payment! Waiting for Blockchain confirmation.'});
			showSettleModal = false;
		}
		submitting = false;
	}

	async function openSettle(e, group_uuid, currency){
		e.target.parentElement.disabled = true;
		let d = await makeAuthenticateCall('/simplifyuserdebts', {
			group: group_uuid
		});
		e.target.parentElement.disabled = false;
		if (!d.success){
			alert('Could not fetch info for settlement!')
			return;
		}
		d = d.data;
		const groupIndex = groupIndexes.indexOf(group_uuid);
		if (groups[groupIndex].pendingPayment){
			for (let i=0; i<d.owes.length; i++){
				const checkPending = groups[groupIndex].pendingPayment.indexOf(d.owes[i].member.uuid);
				if (checkPending != -1){
					d.owes[i].pendingPayment = true;
				}
			}
		}
		settlementPreview = {
			group: group_uuid,
			currency: currency,
			members: d
		};
		showSettleModal = true;
	}
</script>

<svelte:head>

	<title>Groups </title>
</svelte:head>
{#if loginModal}
	<Login/>
{/if}
{#if showGroupModal}
	<Group on:close="{(g) => {
		if (g.detail) {
			getGroups();
		}
		showGroupModal = false;
	}}" />
{/if}
<div id="grouptab" class="col s12">
	<h3>Groups</h3>
	<div class="row">
	<div class="mdc-ripple-surface">
		<button class="mdc-button mdc-button--raised" on:click={(event)=> {event.preventDefault(); showGroupModal = true; }}>Create New Group
		</button>
		</div>
	</div>
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
					{#each groups as group}
						<tr>
						<td on:click={() => {goto('/groups/'+group.uuid)}}>{group.name}</td>
						<td>
						{#if group.totalOwes-group.totalOwed > 0}
							{getFormattedMoney((group.totalOwes-group.totalOwed)/100, group.currency)}
								{#if showGroups && localGroups.length > 0}
									<button class="mdc-button mdc-button--dense" disabled>Settling Disabled</button>
								{:else}
									<button class="mdc-button mdc-button--raised mdc-button--dense" on:click={(e) => openSettle(e, group.uuid, group.currency)}>Settle</button>
								{/if}
						{:else if group.totalOwes-group.totalOwed < 0}
							{getFormattedMoney((group.totalOwed-group.totalOwes)/100, group.currency)}
							<button class="mdc-button mdc-button--raised mdc-button--dense grey" on:click={(e) => openSettle(e, group.uuid, group.currency)}>Owed</button>
						{:else}
							<button class="mdc-button mdc-button--dense" disabled>All Settled</button>
						{/if}
						{#if group.pendingBills > 0}
						<button class="mdc-button mdc-icon-button">
							<i class="material-icons tooltipped" data-position="top" data-tooltip={group.pendingBills>1 ? group.pendingBills+" Bills are pending on Blockchain" : group.pendingBills+" Bill is pending on Blockchain"}>sync</i>
						</button>
						{/if}
						</td>
						<td><button class="mdc-button mdc-button--dense mdc-button--outlined" on:click={() => {goto('/groups/'+group.uuid)}}>Details</button></td></tr>
					{/each}
			</tbody>
		</table>
		{:else}
			We will show group details once you have created a group.
		{/if}
	{:else if localGroups && localGroups.length > 0}
		We could not fetch groups. Try again later.
	{:else}
		Fetching groups..
	{/if}
	</div>
</div>
