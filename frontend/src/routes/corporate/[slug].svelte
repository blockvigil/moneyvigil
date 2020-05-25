<style>
	.hlite {
		background: orange !important;
		transition-property: background;
		transition-duration: 1s;
		transition-timing-function: ease-in-out;
	}
	.hliteoff {
		transition-property: background;
		transition-duration: 1s;
		transition-timing-function: ease-in-out;
	}
	.showSolidborder {
		border-bottom: 2px solid #6200ee;
	}
	.showDottedborder {
		border-bottom: 2px dotted #6200ee;
	}
	.pastbills {
		border-left: 5px solid #6200ee;
	}
	.pastbills button {
		color: grey !important;
		border-color: grey !important;
	}
</style>

<script>
	import { onMount, tick } from 'svelte';
	import { goto, stores } from '@sapper/app';
	const { page } = stores();
	import { loginModalStore, userUUID, wsBillStore } from '../../stores.js';
	import { isLoggedIn, checkUser, makeAuthenticateCall, initialize, initWS, receiptPrefix, getFormattedMoney, setRippleButtons, checkMetaMask, signMessage, ensDomain, setToolTips } from '../../common.js';
	import Modal from '../../components/Modal.svelte';
	import Login from '../../components/Login.svelte';
	import Group from '../../components/Group.svelte';
	import Invite from '../../components/InviteEmployee.svelte';

	let showSplitModal = false;
	let loginModal = false;
	let payments = [];
	let paymentIndexes = [];
	let submitting = false;
	let currentBill = {};
	let showDeleteBillModal = false;
	let selectedEmployee = false;
	let employeeNames = [];
	let role = '';
	let employeeAutoFillData = {};

	const unsubscribeLGM = loginModalStore.subscribe(value => {
		loginModal = value;
	});
	let userUUID_value = '';
	const unsubscribeUID = userUUID.subscribe(value => {
		userUUID_value = value;
	});

	let {slug} = $page.params;
	slug = slug.split('_');
	let entity_uuid = slug[0];
	let entity_name = slug.slice(1).join('_');

	export let uuid = '';
	export let email = "";
	let prevEmail = "";
	let validEmail = false;
	let emailCheckTimeout;
	let isUser = {};
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
		if (selectedEmployee !== false && role){
			createEnabled = true;
			setRippleButtons();
		} else {
			createEnabled = false;
		}
	}

	onMount(() => {
		if (isLoggedIn()){
			//getEntities();
			getGroups();
			getEmployees();
			getEntityInfo();
		} else {
			loginModal = true;
		}
		initialize();
	});
	let bills = [];
	let billIndexes = [];
	let selectedBill;
	let members = [];
	let owed = [];
	let owes = [];
	let showBills = false;
	let localBills = [];
	let showMembers = false;
	let localMembers = [];
	let entity = {};
	let currentGroup = {};
	let groups = [];
	let entities = [];
	let groupIndexes = [];
	let showGroups = false;
	let localGroups = [];
	let settlementPreview = {}
	let showSettleModal = false;
	let showManageModal = false;
	let showInvite = false;
	let domain = "@blockvigil.com";
	let globalPermissions = [];

	async function getEntities(fetched){
		showSettleModal = false;
		var d;
		d = await makeAuthenticateCall('/user/');
		entities = d.user.connectedEntities;
		for (let i=0; i<entities.length; i++){
			if (entity_uuid == entities[i].entity.uuid){
				entity = entities[i].entity;
			}
		}
		//console.log('got entities', entities);
		setToolTips();
	}

	async function getEntityInfo(){
		var d = await makeAuthenticateCall('/corporateEntity/'+entity_uuid);
		entity = d;
		console.log(d);
	}

	async function createGroup(event, uuid, name){
		console.log('create group', event);
		if (event){
			event.target.disabled = true;
		}
		var d = await makeAuthenticateCall('/corporateEntity/'+entity_uuid+'/group/', {
			entityUUID: entity_uuid,
			name: name+' - '+entity.name,
			currency: "USD",
			employee: {
				uuid: uuid
			},
		});
		if (!d.success){
			alert('Could not create group');
			if (event){
				event.target.disabled = false;
			}
			return;
		}
		M.toast({html: 'Create group for '+name});
		getGroups();
		getEmployees();
	}

	async function getEmployees(fetched){
		showMembers = false;
		var d;
		if (fetched){
			d = fetched;
		} else {
			localMembers = JSON.parse(localStorage.getItem(userUUID_value+'_employees_'+entity_uuid));
			d = localMembers;
		}
		if (d){
			members = d.users;
			employeeAutoFillData = {}
			for (let i=0; i<members.length; i++){
				employeeAutoFillData[members[i].name] = null;
				employeeNames.push(members[i].name);
			}
		}
		if (!fetched){
			var d = await makeAuthenticateCall('/corporateEntity/'+entity_uuid+'/users/');
			if (d.success){
				localMembers = [];
				await getEmployees(d);
				//localStorage.setItem(userUUID_value+'_groupmembers_'+entity_uuid, JSON.stringify(d));
			} else {
				if (localMembers && localMembers.members.length > 0){
					showMembers = true;
				}
				localMembers = [""];
			}
		} else {
			showMembers = true;
		}
		if (!d){
			return;
		}
	}

	async function addGroupPermission(event){
		if (event){
			event.target.disabled = true;
		}
		let data = {
			entityUUID: entity_uuid,
			groupUUID: currentGroup.uuid
		}
		if (role == 'disburser'){
			data.disbursers = [{
				eth_address: members[selectedEmployee].connectedAddresses[0],
				uuid: members[selectedEmployee].uuid
			}];
		} else {
			data.approvers = [{
				eth_address: members[selectedEmployee].connectedAddresses[0],
				uuid: members[selectedEmployee].uuid
			}];
		}
		let d = await makeAuthenticateCall('/corporateEntity/'+entity_uuid+'/group/'+currentGroup.uuid+'/'+(role == 'disburser' ? 'disbursers' :'approvers'), data);
		if (!d.success){
			alert('Could not add role');
			if (event){
				event.target.disabled = false;
			}
			return;
		}
		M.toast({html: 'Added '+members[selectedEmployee].name+' as '+role+' to group '});
		showManageModal = false;
		getEmployees();
	}

	async function getGroups(fetched){
		showGroups = false;
		showSettleModal = false;
		var d;
		if (fetched !== undefined){
			if (fetched){
				d = fetched;
			}
		} else {
			console.log(userUUID_value+'_entitygroups_'+entity_uuid);
			localGroups = JSON.parse(localStorage.getItem(userUUID_value+'_entitygroups_'+entity_uuid));
			d = localGroups;
		}
		if (d){
			groups = d.groups;
			if (d.globalRoles.length > 0){
				globalPermissions = d.globalRoles[0].permissions;
			}
			groupIndexes = [];
			for (let i=0; i<groups.length; i++){
				console.log(groups[i]);
				groupIndexes.push(groups[i].uuid);
				if (entity_uuid == groups[i].uuid){
					group = groups[i];
				}
			}
		}
		if (!fetched){
			d = await makeAuthenticateCall('/user/corporateEntity/'+entity_uuid+'/groups');
			if (d.success){
				localGroups = [];
				await getGroups(d);
				localStorage.setItem(userUUID_value+'_entitygroups_'+entity_uuid, JSON.stringify(d));
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

</script>

<svelte:head>

	<title>Groups > {entity && entity.name ? entity.name : entity_name} </title>
</svelte:head>
{#if loginModal}
	<Login/>
{/if}
{#if showManageModal}
	<Modal disableOk={true} on:close={() => { showManageModal = false;
		}}>
		<h4>Manage Group - {currentGroup.name}</h4>
		<div class="row">
			<div class="input-field col s3">
				<select id="role" bind:value={role}>
				<option value="" disabled selected>Choose</option>
				<option value="approver">Approver</option>
				<option value="disburser">Disburser</option>
				</select>
				<label>Role</label>
			</div>
			<div class="input-field col s12 m7">
				<input type="text" id="employees-input" class="autocomplete" placeholder="" autocomplete="new-password">
				<label for="employees-input">Select employee</label>
			</div>
		</div>
		<div slot="action" class="left">
			{#if createEnabled}
			<button class="mdc-button mdc-button--raised" type="submit" data-intercom-target="Create Group" on:click={addGroupPermission}>
				<span class="mdc-button__label">Add {(isUser.name && isUser.uuid != userUUID_value) ? isUser.name : ''} as Role</span>
				<i class="material-icons mdc-button__icon right">send</i>
			</button>
			{:else}
			<button class="mdc-button mdc-button--raised" type="submit" data-intercom-target="Create Group" on:click={addGroupPermission} disabled>
				<span class="mdc-button__label">Add {(isUser.name && isUser.uuid != userUUID_value) ? isUser.name : ''} Role</span>
				<i class="material-icons mdc-button__icon right">send</i>
			</button>
			{/if}
		</div>
	</Modal>
{/if}
{#if showInvite}
	<Invite entity={entity_uuid} inviteEmail={domain} on:close="{() => {
		showInvite = false;
		(async () => {
			console.log('added employee');
			getEmployees();
			/*
			isUser = await checkUser(email);
			await tick();
			const elems = document.querySelectorAll('select');
			const instances = M.FormSelect.init(elems);
			*/
		})();
	}}" />
{/if}
<div id="grouptab" class="col s12">
	<h3>Entity - {entity && entity.name ? entity.name : entity_name}</h3>
	{#if entity && entity.name}
	<div class="row">
		<table id="groups" class="striped">
			<thead>
				<tr>
					<th>Type</th><th>Details</th>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td>Address</td><td>{entity.contract} <button class="mdc-button mdc-button--dense mdc-button--outlined" on:click={() => {
						navigator.clipboard.writeText(entity.name+'.'+ensDomain).then(function() {
							M.toast({html: 'Copied!'});
						});

					}}>{entity.name}.{ensDomain}</button></td>
				</tr>
				<tr>
					<td>Compound Balance</td><td>{(entity.cDaiBalance/1000000000000000000).toFixed(2)} (excludes interest)</td>
				</tr>
				<tr>
					<td>Dai Balance</td><td>{(entity.daiBalance/1000000000000000000).toFixed(2)} (in contract)</td>
				</tr>
				<tr>
					<td>Corp Email</td><td>{entity.email}</td>
				</tr>
			</tbody>
		</table>
	</div>
	{/if}
	<h4>Groups</h4>
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
						<td on:click={() => {goto('/expenses/'+group.uuid+'_'+entity_uuid)} }>{group.name}</td>
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
						{#if globalPermissions.indexOf('CAN_ADD_APPROVER') != -1 || globalPermissions.indexOf('CAN_ADD_DISBURSER') != -1 || group.permissions.indexOf('CAN_ADD_APPROVER') != -1 || group.permissions.indexOf('CAN_ADD_DISBURSER') != -1}
						<td><button class="mdc-button mdc-button--dense mdc-button--outlined" on:click={() => {currentGroup = group; showManageModal = true;
							(async () => {
								//getEmployees();
								await tick();
								const elems = document.querySelectorAll('select');
								const instances = M.FormSelect.init(elems);
								let autoCompleteElement = document.querySelector('#employees-input');
								if (!autoCompleteElement){
									console.log('not loaded');
									return;
								}
								let instance = M.Autocomplete.getInstance(autoCompleteElement);
								instance = M.Autocomplete.init(autoCompleteElement, {
									data: employeeAutoFillData,
									minLength: 0,
									limit: 10,
									onAutocomplete: function(d){
										const pos = employeeNames.indexOf(d);
										console.log('set', d, pos);
										if (members[pos].connectedAddresses.length == 0){
											selectedEmployee = false;
											alert('This employee has not added a wallet address!');
										} else {
											selectedEmployee = pos;
										}
									}
								});
								instance.open();
							})()
							}}>Manage</button></td>
						{/if}
						<td><button class="mdc-button mdc-button--dense mdc-button--outlined" on:click={() => {goto('/expenses/'+group.uuid+'_'+entity_uuid)}}>Details</button></td></tr>
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
	<h4>Employees</h4>
	{#if globalPermissions.indexOf('CAN_ADD_EMPLOYEE') != -1}
	<div class="row">
		<div class="col s12">
			<button class="mdc-button mdc-button--raised" on:click={(event)=> {event.preventDefault(); showInvite = true; }}>Add New
			</button>
		</div>
	</div>
	{/if}
	<div class="row">
		{#if showMembers && localMembers.length > 0}
			<span class="helper-text red-text">Using offline data for employees</span>
		{/if}
		<div class="col s12">
		<table id="members" class="striped">
			<thead>
				<tr>
					<th>Name</th><th>Email</th><th>Action</th>
				</tr>
			</thead>
			<tbody>
			{#if showMembers}
				{#each members as member}
					<tr>
						<td>{member.name}</td>
						<td>{member.email}</td>
						<td>
						{#if member.groups.length == 0}
						<button class="mdc-button mdc-button--raised" on:click={(event) => {
							createGroup(event, member.uuid, member.name)
						}}>Create Group
						</button>
						{:else}
						<button class="mdc-button mdc-button--outlined" on:click={() => {goto('/expenses/'+member.groups[0].uuid+'_'+entity_uuid)}}>
							<span class="mdc-button__label">Manage Expenses</span>
							<i class="material-icons mdc-button__icon right">receipt</i>
						</button>
						{/if}
						</td>
					</tr>
				{/each}
			{:else if localMembers && localMembers.length > 0}
				We could not fetch employees. Try again later.
			{:else}
				Fetching employees..
			{/if}
			</tbody>
		</table>
		</div>
	</div>
</div>
