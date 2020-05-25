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
	import { onMount } from 'svelte';
	import { tick } from 'svelte';
	import { goto, stores } from '@sapper/app';
	const { page } = stores();
	import { loginModalStore, userUUID, wsBillStore } from '../../stores.js';
	import { isLoggedIn, checkUser, makeAuthenticateCall, initialize, initWS, receiptPrefix, getFormattedMoney, checkMetaMask, signMessage, setToolTips } from '../../common.js';
	import Modal from '../../components/Modal.svelte';
	import Login from '../../components/Login.svelte';
	import Group from '../../components/Group.svelte';

	let showSplitModal = false;
	let loginModal = false;
	let payments = [];
	let pendingBills = [];
	let paymentIndexes = [];
	let submitting = false;
	let currentBill = {};
	let showDeleteBillModal = false;

	const unsubscribeLGM = loginModalStore.subscribe(value => {
		loginModal = value;
	});
	let userUUID_value = '';
	const unsubscribeUID = userUUID.subscribe(value => {
		userUUID_value = value;
	});

	const unsubscribeWBL = wsBillStore.subscribe(value => {
		if (value.confirmed){
			getGroups(null);
			showGroups = false;
		}
		const paymentCount = payments.length;
		const billCount = pendingBills.length;
		if ((payments.length > 0 || pendingBills.length > 0) && value && value.hash){
			//#FIXME Not going to work - we need hashes, below has UUIDs FFS
			const billIndex = billIndexes.indexOf(value.hash);
			if (1 || billIndex != -1){
				if (value.state == 'BillSubmitted'){
					payments = payments.filter(b => b.uuidHash != value.hash);
					pendingBills = pendingBills.filter(b => b.uuidHash != value.hash);
					paymentIndexes = paymentIndexes.filter(b => b != value.hash);
					setTimeout(() => {
						getBills(null);
					}, 2000);
				}
			} else{
				//Probably got someone else's hash
				//console.error('got bad hash', value);
			}
			if (paymentCount > 0 && paymentIndexes.length == 0){
				M.toast({html: 'All payments confirmed on Blockchain!'});
			}
			if (billCount > 0 && pendingBills.length == 0){
				M.toast({html: 'All bills approved on Blockchain!'});
			}
		}
	});

	let {slug} = $page.params;
	slug = slug.split('_');
	let group_uuid = slug[0];
	let group_name = slug.slice(1).join('_');

	onMount(() => {
		if (isLoggedIn()){
			getGroups();
			getBills();
			getMembers();
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
	let group = {};
	let groups = {};
	let groupIndexes = [];
	let showGroups = false;
	let localGroups = {};
	let settlementPreview = {}
	let showSettleModal = false;
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
				if (group_uuid == groups[i].uuid){
					group = groups[i];
				}
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
			if (group.uuid){
				showGroups = true;
			} else {
				alert('Group not found!');
			}
			setToolTips();
		}
	}

	async function getBills(fetched){
		showBills = false;
		var d;
		if (fetched){
			d = fetched;
		} else {
			localBills = JSON.parse(localStorage.getItem(userUUID_value+'_groupbills_'+group_uuid));
			d = localBills;
		}
		if (d){
			bills = [];
			billIndexes = [];
			d = d.bills;
			for (let i=0; i<d.length; i++){
				d[i].me = {
					share: d[i].bill.expenseMap[userUUID_value] ? d[i].bill.expenseMap[userUUID_value].owes: 0,
					paid: d[i].bill.expenseMap[userUUID_value] ? d[i].bill.expenseMap[userUUID_value].paid: 0
				}
				billIndexes.push(d[i].bill.uuid);
				bills = [...bills, d[i]];
			}
		}
		if (!fetched){
			var d = await makeAuthenticateCall('/group/'+group_uuid+'/billSplits');
			if (d.success){
				localBills = [];
				await getBills(d);
				localStorage.setItem(userUUID_value+'_groupbills_'+group_uuid, JSON.stringify(d));
			} else {
				if (localBills && localBills.bills.length > 0){
					showBills = true;
				}
				localBills = [""];
			}
		} else {
			showBills = true;
			for (let i=0; i<bills.length; i++){
				bills[i].prevBills = [];
				if (!bills[i].bill.childBill && bills[i].bill.prevBill){
					let bill = bills[i];
					while (bill.bill.prevBill){
						bill = bills[billIndexes.indexOf(bill.bill.prevBill.uuid)]
						bills[i].prevBills.push(bill)
					}
				}
			}
		}
	}

	function showReceipt(){
		M.toast({html: 'Fetching...'});
	}

	function showSplit(bill_uuid){
		selectedBill = bills[billIndexes.indexOf(bill_uuid)];
		showSplitModal = true;
	}

	async function getMembers(fetched){
		showMembers = false;
		var d;
		if (fetched){
			d = fetched;
		} else {
			localMembers = JSON.parse(localStorage.getItem(userUUID_value+'_groupmembers_'+group_uuid));
			d = localMembers;
		}
		if (d){
			members = d.members;
		}
		if (!fetched){
			var d = await makeAuthenticateCall('/group/'+group_uuid+'/members');
			if (d.success){
				localMembers = [];
				await getMembers(d);
				localStorage.setItem(userUUID_value+'_groupmembers_'+group_uuid, JSON.stringify(d));
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

	async function payCheck (event, item) {
		event.target.parentElement.disabled = true;
		if (0 && await checkMetaMask()){
			const signature = await signMessage({
				type: "Disbursal",
				amount: item.amount,
				group: group.address,
				member: item.member.uuid
			})
			const response = await makeAuthenticateCall('/bill/'+uuid+'/', {
					action: 'disburse',
					message: signature.msgParams,
					signature: signature.result,
					from: signature.from
				}
			);
			if (response.success){
				M.toast({html: 'Bill Disbursal is now being processed!'});
				return true;
			} else {
				alert('Something went wrong');
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

	async function approveBill (event, uuid) {
		event.preventDefault();
		event.target.disabled = true;
		if (await checkMetaMask()){
			const signature = await signMessage({
				type: "Approval",
				group: group.address,
				bill: uuid
			})
			if (!signature){
				event.target.disabled = false;
				return;
			}
			const response = await makeAuthenticateCall('/bill/'+uuid+'/', {
					action: 'approve',
					message: signature.msgParams,
					signature: signature.result,
					from: signature.from
				}
			);
			if (response.success){
				const bill = bills[billIndexes.indexOf(uuid)];
				pendingBills = [...pendingBills, bill];
				event.target.innerHTML = 'pending approval';
				initWS();
				M.toast({html: 'Bill Approval is now being processed!'});
			} else {
				alert('Something went wrong');
				event.target.disabled = false;
			}
		} else {
			alert('You need Metamask');
			event.target.disabled = false;
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
		var d = await makeAuthenticateCall('/bill/', {
			expenseMap: expenseMap,
			group: group_uuid,
			description: 'Payment settlement',
			date: (new Date()).toString(),
			totalAmount: totalAmount
		});
		if (!d.success){
			e.target.parentElement.disabled = false;
			M.toast({html: 'Could not add payment! Try again later.'});
		}
		else {
			paymentIndexes = [...paymentIndexes, d.bill.uuidHash];
			payments = [...payments, d.bill];
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
		e.target.disabled = true;
		let d = await makeAuthenticateCall('/group/'+group_uuid+'/simplifiedDebtGraph');
		e.target.disabled = false;
		if (!d.success){
			alert('Could not fetch info for settlement!');
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

	async function deleteBill(e, uuid){
		console.log('deleting', uuid);
		e.target.disabled = true;
		let d = await makeAuthenticateCall('/deletebill', {
			prevBillUUID: uuid,
			date: (new Date()).toString(),
		});
		e.target.disabled = false;
		if (!d.success){
			alert('Could not delete bill!');
			return;
		}
		console.log(d);
		showDeleteBillModal = false;
		M.toast({html: 'Bill marked for deletion! Awaiting blockchain confirmation...'});
		getBills();
	}

	function highlightBill(uuid){
		const pos = billIndexes.indexOf(uuid);
		bills[pos].show = true;
		setTimeout(() => {
			//bills[pos].show = false;
		}, 1000);
	}

</script>

<svelte:head>

	<title>Groups > {group.name ? group.name : group_name} </title>
</svelte:head>
{#if loginModal}
	<Login/>
{/if}
{#if showGroupModal}
	<Group groupName={group.name} uuid={group.uuid} on:close="{(g) => {
		if (g.detail) {
			getMembers();
		}
		showGroupModal = false;
	}}" />
{/if}
{#if showDeleteBillModal}
<Modal on:close="{() => showDeleteBillModal = false}" disableOk={true}>
 Are you sure you want to delete bill? {currentBill.uuid}

 <button class="mdc-button mdc-button--raised" on:click={(event) => {deleteBill(event, currentBill.uuid)}}>
	 <span class="mdc-button__label loading">Delete Bill</span>
	 </button>
</Modal>
{/if}
{#if showSplitModal}
<Modal disableCancel={true} on:close="{() => showSplitModal = false}">
	<ul class="collection">
	{#each selectedBill.splits as split}
	<li class="collection-item">{split.debitor.name} owes {split.creditor.name} {getFormattedMoney(split.amount/100, group.currency)}</li>
	{/each}
	</ul>
</Modal>
{/if}
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
<div id="grouptab" class="col s12">
	<h3>Group - {group.name ? group.name : group_name}</h3>
	{#if (showGroups && showBills && bills.length > 0) }
	<div class="row">
		<div class="col s12">
		{#if group.totalOwes-group.totalOwed > 0}
			{getFormattedMoney((group.totalOwes-group.totalOwed)/100, group.currency)}
				{#if showGroups && localGroups.length > 0}
					<button class="mdc-button mdc-button--raised" disabled>Settling Disabled</button>
				{:else}
					<button class="mdc-button mdc-button--raised" on:click={(e) => openSettle(e, group.uuid, group.currency)}>Settle</button>
				{/if}
		{:else if group.totalOwes-group.totalOwed < 0}
			{getFormattedMoney((group.totalOwed-group.totalOwes)/100, group.currency)}
			<button class="mdc-button mdc-button--raised grey" on:click={(e) => openSettle(e, group.uuid, group.currency)}>Owed</button>
		{:else}
			<button class="mdc-button" disabled>All Settled</button>
		{/if}
		{#if group.pendingBills > 0}
		<button class="mdc-button mdc-icon-button">
			<i class="material-icons tooltipped" data-position="right" data-tooltip={group.pendingBills>1 ? group.pendingBills+" Bills are pending on Blockchain" : group.pendingBills+" Bill is pending on Blockchain"}>sync</i>
		</button>
		{/if}
		</div>
	</div>
	<h4>Bills</h4>
	{/if}
	{#if showBills && localBills.length > 0}
		<span class="helper-text red-text">Using offline data for bills</span>
	{/if}
	<div class="row">
		<div class="col s12">
			<button class="mdc-button mdc-button--raised" on:click={() => {goto('/?group='+group.name)}}>Add Bill</button>
		</div>
	</div>
	{#if members.length == 1}
	<div class="row">
		<div class="col s12">
			<button class="mdc-button mdc-button--raised" on:click={() => {
				localStorage.setItem('fixedGroup', group.name);
				localStorage.setItem('fixedGroupUUID', group.uuid);
				}}>Set as Corporate</button>
		</div>
	</div>
	{/if}
	<div class="row">
		<div class="col s12">
	{#if showBills && showGroups}
		{#if bills.length > 0}
			<table id="bills" class="striped responsive-table">
				<thead>
					<tr>
						<th>Description</th><th>Date</th><th>Amount</th><th>Share</th><th>Paid</th><th>Splits</th><th>Receipt</th>
					</tr>
				</thead>
				<tbody>
				{#if showBills}
					{#each bills.filter((bill) => !bill.bill.childBill)  as bill}
						<tr class={bill.show ? 'hlite' : 'hliteoff'}>
							<td style="max-width: 156px"><span class="truncate">{bill.bill.metadata.description}</span></td>
							<td style="max-width: 156px"><span class="truncate">{bill.bill.metadata.date}</td>
							{#if bill.bill.state == 'submitted'}
								{#if bill.bill.metadata.linkage != 'delete'}
								<td>{getFormattedMoney(bill.bill.metadata.totalAmount/100, group.currency)}</td>
								<td>{getFormattedMoney(bill.me.share/100, group.currency)}</td>
								<td>{getFormattedMoney(bill.me.paid/100, group.currency)}</td>
								<td>
									<button class="mdc-button mdc-button--outlined" on:click={() => {showSplit(bill.bill.uuid)}}>
										<span class="mdc-button__label">Show Splits</span>
										<i class="material-icons mdc-button__icon right">call_split</i>
									</button>
									{#if bill.bill.childBill}
										{#if bill.bill.childBill.linkage == 'delete'}
										<button class="mdc-button mdc-button--outlined">
											Deleted
										</button>
										{/if}
									{:else}
										<button class="mdc-button mdc-button--outlined" on:click={() => {
											showDeleteBillModal = true;
											currentBill = {
												uuid: bill.bill.uuid,
											}
										}}>
											<span class="mdc-button__label">Delete</span>
											<i class="material-icons mdc-button__icon right">delete_forever</i>
										</button>
										<button class="mdc-button mdc-button--outlined" on:click={() => {goto('/?bill='+bill.bill.uuid)}}>
											<span class="mdc-button__label">Edit</span>
											<i class="material-icons mdc-button__icon right">edit</i>
										</button>
									{/if}
									{#if bill.bill.prevBill}
										<button class="mdc-button mdc-button--outlined" on:click={() => {highlightBill(bill.bill.prevBill.uuid)}}>
											See older Parent
										</button>
									{/if}
									</td>
								{:else}
								<td colspan="3"></td>
								<td>
								<button class="mdc-button mdc-button--outlined" on:click={() => {highlightBill(bill.bill.prevBill.uuid)}}>
									See reversee Parent
								</button>
								</td>
								{/if}
							{:else}
							<td>{getFormattedMoney(bill.bill.metadata.totalAmount/100, group.currency)}</td>
							<td>{getFormattedMoney(bill.me.share/100, group.currency)}</td>
							<td>{getFormattedMoney(bill.me.paid/100, group.currency)}</td>
							<td>
								{#if group.approval_required}
								<button class="mdc-button mdc-button--raised" on:click={(e) => {
									approveBill(event, bill.bill.uuid)
									}}>
									Approve
								</button>
								{:else}
								<button class="mdc-button mdc-button--outlined" disabled>
									Pending
								</button>
								{/if}
							</td>
							{/if}
							<td>
								{#if bill.bill.metadata.fileHash}<a class="mdc-button" href={receiptPrefix+"/"+bill.bill.metadata.fileHash} on:click={() => {
								M.toast({html: 'Fetching...'});
								}} target="_blank"><i class="material-icons mdc-button__icon">cloud_download</i></a>{:else}-{/if}
							</td>
						</tr>
						{#each bill.prevBills as subBill, i}
							{#if subBill.show}
							<tr style={subBill.bill.childBill.linkage == 'delete' ? "text-decoration: line-through;" :  "color:grey"} class={(bill.prevBills[i+1] && !bill.prevBills[i+1].show) ? 'pastbills showDottedborder': (!bill.prevBills[i+1] ? 'pastbills showSolidborder' : 'pastbills')}>
								<td style="max-width: 156px"><span class="truncate">{subBill.bill.metadata.description}</span></td>
								<td style="max-width: 156px"><span class="truncate">{subBill.bill.metadata.date}</td>
								<td>{getFormattedMoney(subBill.bill.metadata.totalAmount/100, group.currency)}</td>
								<td>{getFormattedMoney(subBill.me.share/100, group.currency)}</td>
								<td>{getFormattedMoney(subBill.me.paid/100, group.currency)}</td>
								<td style="text-decoration: none;">
								{#if subBill.bill.state == 'submitted'}
									{#if subBill.bill.metadata.linkage != 'delete'}
										<button class="mdc-button mdc-button--outlined" on:click={() => {showSplit(subBill.bill.uuid)}}>
											<span class="mdc-button__label">Show Splits</span>
											<i class="material-icons mdc-button__icon right">call_split</i>
										</button>
										{#if subBill.bill.childBill.linkage == 'delete'}
										<!--
										<button class="mdc-button mdc-button--outlined">
											D
										</button>
										-->
										{/if}
										{#if subBill.bill.prevBill && !subBill.dontShow}
											<button class="mdc-button mdc-button--outlined" on:click={() => {
												highlightBill(subBill.bill.prevBill.uuid);
												subBill.dontShow = true;
												}}>
												<i class="material-icons mdc-button__icon right">keyboard_arrow_down</i>
											</button>
										{/if}
										{#if !bill.prevBills[i+1] || !bill.prevBills[i+1].show}
											<button class="mdc-button mdc-button--outlined" on:click={() => {
												bills[billIndexes.indexOf(subBill.bill.uuid)].show = false;
												if (i > 0){
													bill.prevBills[i-1].dontShow = false;
												}
											}}>
												<i class="material-icons mdc-button__icon right">keyboard_arrow_up</i>
											</button>
										{/if}
									{/if}
								{:else}
									<button class="mdc-button mdc-button--outlined" disabled>
										Pending
									</button>
								{/if}
								</td>
								<td>
									{#if subBill.bill.metadata.fileHash}<a class="mdc-button" href={receiptPrefix+"/"+subBill.bill.metadata.fileHash} on:click={() => {
									M.toast({html: 'Fetching...'});
									}} target="_blank"><i class="material-icons mdc-button__icon">cloud_download</i></a>{:else}-{/if}
								</td>
							</tr>
							{/if}
						{/each}
					{/each}
				{:else if localBills && localBills.length > 0}
					We could not fetch bills. Try again later.
				{:else}
					Fetching bills..
				{/if}
				</tbody>
			</table>
		{:else}
		There are no bills created in this group.
		{/if}
	{:else if localBills && localBills.length > 0}
		We could not fetch bills. Try again later.
	{:else}
		Fetching bills..
	{/if}
		</div>
	</div>
	<h4>Members</h4>
	<div class="row">
		<div class="col s12">
			<button class="mdc-button mdc-button--raised" on:click={(event)=> {event.preventDefault(); showGroupModal = true; }}>Add New
			</button>
		</div>
	</div>
	<div class="row">
		{#if showMembers && localMembers.length > 0}
			<span class="helper-text red-text">Using offline data for members</span>
		{/if}
		<div class="col s12">
		<table id="members" class="striped">
			<thead>
				<tr>
					<th>Name</th><th>Email</th>
				</tr>
			</thead>
			<tbody>
			{#if showMembers}
				{#each members as members}
					<tr><td>{members.name}</td><td>{members.email}</td></tr>
				{/each}
			{:else if localMembers && localMembers.length > 0}
				We could not fetch members. Try again later.
			{:else}
				Fetching members..
			{/if}
			</tbody>
		</table>
		</div>
	</div>
</div>
