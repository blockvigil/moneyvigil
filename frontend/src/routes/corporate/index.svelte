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
			getEntities();
		}
		await initialize();
		const elems = document.querySelectorAll('select');
		const instances = M.FormSelect.init(elems);
	});
	let settlementPreview = {}
	let showGroupModal = false;

	async function getEntities(fetched){
		showGroups = false;
		showSettleModal = false;
		var d;
		d = await makeAuthenticateCall('/user/');
		localGroups = [];
		groups = d.user.connectedEntities;
		//console.log('got entities', groups);
		groupIndexes = [];
		for (let i=0; i<groups.length; i++){
			groupIndexes.push(groups[i].entity.uuid);
		}
		showGroups = true;
		setToolTips();
	}

</script>

<svelte:head>

	<title>Entities</title>
</svelte:head>
{#if loginModal}
	<Login/>
{/if}
{#if showGroupModal}
	<Group on:close="{(g) => {
		if (g.detail) {
			getEntities();
		}
		showGroupModal = false;
	}}" />
{/if}
<div id="grouptab" class="col s12">
	<h3>Entities</h3>
	<div class="row">
	<div class="mdc-ripple-surface">
		<button class="mdc-button mdc-button--raised" on:click={() => {goto('/corporate/new')}}>Create New Entity
		</button>
		</div>
	</div>
	<div class="row">
	{#if showGroups && localGroups.length > 0}
		<span class="helper-text red-text">Using offline data for groups</span>
	{/if}
	{#if showGroups}
		{#if groups.length > 0}
		<table id="groups" class="striped">
			<thead>
				<tr>
					<th>Name</th><th>Roles</th><th>Manage</th>
				</tr>
			</thead>
			<tbody>
					{#each groups as group}
						<tr>
						<td on:click={() => {goto('/groups/'+group.entity.uuid)}}>{group.entity.name}</td>
						<td>
						{#each group.roles as role, i}
						<div class="chip">
							<span>{role.name}</span>
						</div>
						{/each}
						</td>
						<td><button class="mdc-button mdc-button--dense mdc-button--outlined" on:click={() => {goto('/corporate/'+group.entity.uuid)}}>Manage </button></td></tr>
					{/each}
			</tbody>
		</table>
		{:else}
			We will show entity details once you have created an entity.
		{/if}
	{:else if localGroups && localGroups.length > 0}
		We could not fetch entities. Try again later.
	{:else}
		Fetching entities..
	{/if}
	</div>
</div>
