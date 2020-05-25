<script>
	import { onMount, onDestroy, tick } from 'svelte';
	import { goto } from '@sapper/app';
	import { fade } from 'svelte/transition';
	import { Decimal} from 'decimal.js';
	import { loginModalStore, userUUID, userCurrency, corporateProfileStore, wsBillStore } from '../stores.js';
	import { isLoggedIn, makeAuthenticateCall, initWS, closeWS, initialize, checkUser, fakeUserUUID, setLabels, getFormattedMoney, setRippleButtons, setToolTips, userToken_value, receiptPrefix, apiPrefix } from '../common.js';
	import Modal from '../components/Modal.svelte';
	import Login from '../components/Login.svelte';
	import Group from '../components/Group.svelte';

	let bills = [];
	let unsubmittedBills = [];
	let uploadingPercentage = 0;

	const unsubscribeWBL = wsBillStore.subscribe(value => {
		if (bills.length > 0 && value && value.hash){
			const billIndex = billIndexes.indexOf(value.hash);
			if (billIndex != -1){
				switch (value.state){
					case 'BillCreated':
						bills[billIndex].state = 'Mined';
					break;
					case 'ExpenseAdded':
						bills[billIndex].state = 'Confirming';
					break;
					case 'BillSubmitted':
						bills[billIndex].state = 'Confirmed';
					break;
				}
				if (value.state == 'BillSubmitted'){
					bills = bills.filter(b => b.uuidHash != value.hash);
					billIndexes = billIndexes.filter(b => b != value.hash);
				}
			} else{
				//Probably got someone else's hash
				//console.error('got bad hash', value);
			}
			if (billIndexes.length == 0){
				wsBillStore.set({confirmed: true});
				M.toast({html: 'Pending bills confirmed on Blockchain!'});
			}
		} else {
			if (value.confirmed){
				wsBillStore.set({});
				closeWS();
			}
		}
	});

	let showModal = false;
	var groups = {};
	let urlParams;
	let uploading = false;
	let dummyGroups = false;
	let firstBill = false;
	let dummyGroupData = {};
	let uploadedFileName = '';
	let submitting = false;
	let currentBill = {};
	let fixedGroup = null;
	let fixedGroupUUID = null;

	onDestroy(async () => {
		unsubscribeWBL();
	});

	onMount(async () => {
		if (isLoggedIn()){
			urlParams = new URLSearchParams(window.location.search);
			if (urlParams.get('dummy') || urlParams.get('newuser')){
				dummyGroups = true;
				firstBill = true;
			}
			if (urlParams.get('firstBill')){
				firstBill = true;
			}
			await initialize();
			if (urlParams.get('bill')){
				isSetGroup = true;
				currentBill = {
					fetching: urlParams.get('bill')
				};
			}
			if (urlParams.get('group')){
				await populateGroupMembers();
				setGroup(urlParams.get('group'));
			} else {
				if ($corporateProfileStore){
					goto('/corporate');
					return;
				}
				fixedGroup = localStorage.getItem('fixedGroup');
				fixedGroupUUID = localStorage.getItem('fixedGroupUUID');
				console.log('corporateProfile', $corporateProfileStore);
				if ($corporateProfileStore){
					//isSetGroup = true;
					await populateGroupMembers();
					//setGroup(localStorage.getItem('fixedGroup'));
				} else {
					populateGroupMembers();
				}
			}
			if (currentBill.fetching){
				var d = await makeAuthenticateCall('/bill/'+currentBill.fetching+'/');
				if (!d.uuid){
					console.error('error getting bill', d, currentBill.fetching);
					alert('Sorry, we could not fetch the bill');
					return;
				}
				currentBill = d;
				for (let i in groups){
					if (groups[i].uuid == currentBill.group){
						setGroup(i);
					}
				}
				totalAmount = currentBill.metadata.totalAmount/100;
				description = currentBill.metadata.description;
				fileHash = currentBill.metadata.fileHash;
				if (fileHash){
					var previewImage = document.getElementById('preview');
					previewImage.setAttribute('src', receiptPrefix+"/"+fileHash);
					previewImage.style.display = 'block';
				}
				if (!$corporateProfileStore){
					paidAmountLocked = true;
					owesAmountLocked = true;
				}
				//#FIXME auto remove members that were not in the bill?
				for (let i=0; i<currentGroup.members.length; i++){
					if ($userUUID == currentGroup.members[i].uuid){
						owesAmount = currentBill.expenseMap[currentGroup.members[i].uuid].owes/100;
						paidAmount = currentBill.expenseMap[currentGroup.members[i].uuid].paid/100;
						prevPaidAmount = paidAmount;
						continue;
					}
					currentGroup.members[i].owes = currentBill.expenseMap[currentGroup.members[i].uuid].owes/100;
					currentGroup.members[i].prevOwes = currentBill.expenseMap[currentGroup.members[i].uuid].owes/100;
					currentGroup.members[i].paid = currentBill.expenseMap[currentGroup.members[i].uuid].paid/100;
					currentGroup.members[i].prevPaid = currentBill.expenseMap[currentGroup.members[i].uuid].paid/100;
				}
			}
			getPendingBills();
			await tick();
		}
		const now = new Date();
		let prevQuarter = new Date();
		prevQuarter.setMonth(now.getMonth() - 3);
		const dates = document.querySelectorAll('.datepicker');
		M.Datepicker.init(dates, {
			defaultDate: now,
			setDefaultDate: true,
			autoClose: true,
			yearRange: 0,
			minDate: prevQuarter,
			maxDate: new Date()
		});
	});

	function progressHandler(event) {
		uploadingPercentage = Math.round((event.loaded / event.total) * 100);
	}

	function completeHandler(event) {
		uploadingPercentage = 0;
		let d = JSON.parse(event.target.responseText);
		if (!d.success && !d.fileHash){
			alert('Sorry, could not upload the receipt. Please try later.');
			return;
		}
		description = d.description || description;
		totalAmount = d.amount || totalAmount;
		fileHash = d.fileHash;
		if (d.description || d.amount){
			M.toast({html: 'We scanned and filled some info for you. Feel free to make changes.'});
		} else {
			alert('Sorry, could not find anything in the receipt. Try another one?');
		}
		//document.getElementById("description").focus();
		uploading = false;
	}

	function errorHandler(event) {
		console.error('error uploading');
		alert('Sorry, could not upload the receipt. Please try later.');
		uploading = false;
	}

	function abortHandler(event) {
		console.error('uploading aborted');
		alert('Sorry, could not upload the receipt. Please try later.');
		uploading = false;
	}

	async function checkFile(e){
		e.preventDefault();
		const files = document.getElementById("receipt").files;
		if (files.length > 0){
			uploadedFileName = files[0].name;
			if (!files[0].type.match(/image.*/)) {
				console.error('Non-image', files[0].type);
				alert('We only support images for now. Try taking a picture from your camera.');
				return;
			}
			uploading = true;
			fileHash = '';
			var url = URL.createObjectURL(files[0]);
			var previewImage = document.getElementById('preview');
			var fullImage = document.getElementById('nopreview');
			previewImage.setAttribute('src', url);
			fullImage.setAttribute('src', url);
			fullImage.onload = async function(){
				var canvas = document.getElementById('canvas');
				var ctx = canvas.getContext("2d");
				var MAX_WIDTH = 800;
				var MAX_HEIGHT = 800;
				var width = fullImage.width;
				var height = fullImage.height;

				if (width > height) {
				  if (width > MAX_WIDTH) {
				    height *= MAX_WIDTH / width;
				    width = MAX_WIDTH;
				  }
				} else {
				  if (height > MAX_HEIGHT) {
				    width *= MAX_HEIGHT / height;
				    height = MAX_HEIGHT;
				  }
				}
				canvas.width = width;
				canvas.height = height;
				ctx.drawImage(fullImage, 0, 0, width, height);
				var dataurl = canvas.toDataURL("image/png");
				console.log('compressed from', files[0].size, 'to', dataurl.length*3/4)
				if (Math.round((dataurl.length)*3/4) > 1024*1024*9){
					console.error('File too large', files[0].size);
					alert('Please try a smaller file');
					return;
				}
				//return;
				const blob = await (await fetch(dataurl)).blob();
				const formData = new FormData();
				formData.append('receipt', blob);
				var ajax = new XMLHttpRequest();
				ajax.upload.addEventListener("progress", progressHandler, false);
				ajax.addEventListener("load", completeHandler, false);
				ajax.addEventListener("error", errorHandler, false);
				ajax.addEventListener("abort", abortHandler, false);
				ajax.open("POST", apiPrefix+"/vision");
				ajax.setRequestHeader('Auth-Token', userToken_value);
				ajax.send(formData);
			}
		}
	}
	let showGroups = false;
	let currentGroup = {name: "", members: []};
	let isSetGroup = false;
	let totalAmount = 0;
	let owesAmount = 0;
	let owesAmountLocked = false;
	let prevOwesAmount = 0;
	let paidAmount = 0;
	let paidAmountLocked = false;
	let prevPaidAmount = 0;
	let prevGroupName = ''
	let checkPaidAmount = 0;
	let checkOwesAmount = 0;
	let submitEnabled = false;
	let description = '';
	let localGroups = [];
	let localBills = [];
	let showBills = false;
	let billIndexes = [];
	let showGroupModal = false;
	let validEmail = false;
	let isUser = {};
	let emailCheckTimeout;
	let pendingbillsCheck = false;
	let offlineCheck;
	let descriptionFocused = false;
	let fileHash;

	$: {
		totalAmount = isNaN(totalAmount) || totalAmount > 999999999999  || totalAmount < 0 ? 0 : Number(new Decimal(totalAmount).toFixed(2));
		owesAmount = isNaN(owesAmount) ? 0 : Number(new Decimal(owesAmount).toFixed(2));
		paidAmount = isNaN(paidAmount) ? 0 : Number(new Decimal(paidAmount).toFixed(2));
		if (prevGroupName != currentGroup.name){
			if (isSetGroup){
				isSetGroup = false;
				currentGroup = {name: currentGroup.name, members: []};
			}
			if (/^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/.test(currentGroup.name)){
				validEmail = true;
				isUser.checking = true;
				clearTimeout(emailCheckTimeout);
				emailCheckTimeout = setTimeout(async () => {
					isUser = await checkUser(currentGroup.name)
				}, 500);
			} else {
				validEmail = false;
			}
		}
		if (!owesAmountLocked && prevOwesAmount != owesAmount){
			owesAmountLocked = true;
		}
		if (!owesAmountLocked){
			for (let i=0; i<currentGroup.members.length; i++){
				if (currentGroup.members[i].prevOwes != currentGroup.members[i].owes){
					owesAmountLocked = true;
					break;
				}
			}
		}
		if (!owesAmountLocked){
			owesAmount = currentGroup.members.length > 1 ? Number((new Decimal(totalAmount)).dividedBy(currentGroup.members.length).toFixed(2)) : totalAmount;
			for (let i=0; i<currentGroup.members.length; i++){
				currentGroup.members[i].owes = owesAmount;
				currentGroup.members[i].prevOwes = owesAmount;
			}
			owesAmount = Number((new Decimal(totalAmount)).minus((new Decimal(owesAmount)).times(currentGroup.members.length - 1)).toFixed(2));
			prevOwesAmount = owesAmount;
		}
		if (!paidAmountLocked && prevPaidAmount != paidAmount){
			paidAmountLocked = true;
		}
		if (!paidAmountLocked){
			for (let i=0; i<currentGroup.members.length; i++){
				if (currentGroup.members[i].prevPaid != currentGroup.members[i].paid){
					paidAmountLocked = true;
					break;
				}
			}
		}
		if (!paidAmountLocked){
			paidAmount = totalAmount;
			prevPaidAmount = paidAmount;
		}
		checkPaidAmount = new Decimal(paidAmount);
		checkOwesAmount = new Decimal(0);
		for (let i=0; i<currentGroup.members.length; i++){
			currentGroup.members[i].owes = isNaN(currentGroup.members[i].owes) ? 0 : Number((new Decimal(currentGroup.members[i].owes)).toFixed(2));
			currentGroup.members[i].paid = isNaN(currentGroup.members[i].paid) ? 0 : Number((new Decimal(currentGroup.members[i].paid)).toFixed(2));
			checkOwesAmount = checkOwesAmount.plus(new Decimal(($userUUID == currentGroup.members[i].uuid ? owesAmount : currentGroup.members[i].owes)));
			checkPaidAmount = checkPaidAmount.plus(new Decimal(currentGroup.members[i].paid));
		}
		checkOwesAmount = Number(checkOwesAmount.toFixed(2));
		checkPaidAmount = Number(checkPaidAmount.toFixed(2));
		if (description.trim() == '' || currentGroup.members.length == 0 || totalAmount == 0 || checkOwesAmount != totalAmount || checkPaidAmount != totalAmount){
			submitEnabled = false;
		} else {
			submitEnabled = true;
			setRippleButtons();
		}
	}

	async function doSplit(){
		await tick();
		document.querySelector('#splitButton').disabled = true;
		owesAmount = currentGroup.members.length > 1 ? Number((new Decimal(totalAmount)).dividedBy(currentGroup.members.length).toFixed(2)) : totalAmount;
		for (let i=0; i<currentGroup.members.length; i++){
			currentGroup.members[i].owes = owesAmount;
			currentGroup.members[i].prevOwes = owesAmount;
		}
		prevOwesAmount = owesAmount;
		owesAmountLocked = false;
		await setToolTips();
		document.querySelector('#splitButton').disabled = false;
	}

	async function submitBill(e){
		if (!submitEnabled){
			return false;
		}
		e.preventDefault();
		submitting = true;
		submitEnabled = false;
		let expenseMap = {};
		if ($corporateProfileStore){
			owesAmount = 0;
		}
		for (let i=0; i<currentGroup.members.length; i++){
			if ($corporateProfileStore && $userUUID != currentGroup.members[i].uuid){
				currentGroup.members[i].owes = paidAmount;
			}
			expenseMap[currentGroup.members[i].uuid] = {
				paid: parseInt((new Decimal($userUUID == currentGroup.members[i].uuid ? paidAmount : currentGroup.members[i].paid)).times(100)),
				owes: parseInt((new Decimal($userUUID == currentGroup.members[i].uuid ? owesAmount : currentGroup.members[i].owes)).times(100))
			}
		}
		let billData = {
			expenseMap: expenseMap,
			group: currentGroup.uuid,
			description: description,
			date: document.getElementById("date").value,
			currency: currentGroup.currency,
			fileHash: fileHash || '',
			prevBillUUID: currentBill.uuid,
			totalAmount: totalAmount*100
		};
		if (currentBill.uuid){
			var d = await makeAuthenticateCall('/bill/'+currentBill.uuid+'/', billData, false, false, false, false, 'put');
		} else {
			var d = await makeAuthenticateCall('/bill/', billData);
		}
		submitting = false;
		submitEnabled = true;
		if (d.http_status){
			if (!window.navigator.onLine){
				description = '';
				clearGroup(true);
				totalAmount = 0;
				owesAmount = 0;
				prevOwesAmount = 0;
				paidAmount = 0;
				prevPaidAmount = 0;
				owesAmountLocked = false;
				paidAmountLocked = false;
				fileHash = '';
				M.toast({html: 'Looks like you are offline. We will re-submit transaction when you are back online.'});
				billData.me = {
					share: billData.expenseMap[$userUUID] ? billData.expenseMap[$userUUID].owes: 0,
					paid: billData.expenseMap[$userUUID] ? billData.expenseMap[$userUUID].paid: 0
				}
				billData.failedCount = 0;
				unsubmittedBills = [...unsubmittedBills, billData];
				localStorage.setItem($userUUID+'_unsubmittedbills', JSON.stringify(unsubmittedBills));
				offlineCheck = window.addEventListener('online', submitPending);
			} else {
				alert('Could not reach our servers. Check your internet connection!');
			}
			return;
		}
		if (!d.success){
			console.error(d);
			alert('Could not submit bill. Try again later!');
			return;
		}
		if (firstBill){
			firstBill = false;
		}
		d.bill.me = {
			share: d.bill.expenseMap[$userUUID] ? d.bill.expenseMap[$userUUID].owes: 0,
			paid: d.bill.expenseMap[$userUUID] ? d.bill.expenseMap[$userUUID].paid: 0
		}
		d.bill.state = 'Pending';
		d.bill.transition = true;
		billIndexes = [...billIndexes, d.bill.uuidHash];
		bills = [...bills, d.bill];
		initWS();
		M.toast({html: 'Added Bill! Waiting for Blockchain confirmation.'});
		description = '';
		clearGroup(true);
		totalAmount = 0;
		owesAmount = 0;
		prevOwesAmount = 0;
		paidAmount = 0;
		prevPaidAmount = 0;
		owesAmountLocked = false;
		paidAmountLocked = false;
		fileHash = '';
		currentBill = {};
		document.getElementById("receipt").value = '';
	}


	function removeFriend(uuid){
		currentGroup.members = currentGroup.members.filter(m => m.uuid != uuid);
	}

	async function setGroup(name){
		if (groups[name] == undefined){
			console.error('group not found', name, groups);
			return;
		}
		isSetGroup = true;
		currentGroup = JSON.parse(JSON.stringify(groups[name]));
		if (currentGroup.uuid == ''){
			dummyGroups = false;
			//create the dummy groups in the background
			for (let i in dummyGroupData){
				if (groups[i].uuid){
					continue;
				}
				(function(i){
					setTimeout(async () => {
						var d = await makeAuthenticateCall('/addmember', {
							"name": i,
							"member": fakeUserUUID,
							"group": '',
							"currency": currentGroup.currency
						});
						//This should never happen but let's ensure
						if (!d.success){
							console.error('error creating dummyGroup', i);
							alert('Something went wrong!');
							clearGroup();
						} else {
							groups[currentGroup.name].uuid = d.group.uuid;
							dummyGroupData[currentGroup.name].uuid = d.group.uuid;
							if (i == name){
								currentGroup.uuid = d.group.uuid;
							}
						}
					}, 10);
				})(i);
			}
			/*
			//This should never happen but let's ensure
			if (!d.success){
				console.error('error creating dummyGroup', currentGroup.name)
				alert('Something went wrong!');
				clearGroup();
			} else {
				console.log('setting uuid for dummy group', d.group.uuid);
				currentGroup.uuid = d.group.uuid;
				groups[currentGroup.name].uuid = d.group.uuid;
				dummyGroupData[currentGroup.name].uuid = d.group.uuid;
				await populateGroupMembers(undefined, true);
			}
			}, 10);
			*/
			description = description ? description : currentGroup.description;
			totalAmount = totalAmount ? totalAmount : 100;
		}
		prevGroupName = name;
		for (let i=0; i<currentGroup.members.length; i++){
			currentGroup.members[i].owes = 0;
			currentGroup.members[i].prevOwes = 0;
			currentGroup.members[i].paid = 0;
			currentGroup.members[i].prevPaid = 0;
		}
		await tick();
		setToolTips();
		M.updateTextFields();
		setRippleButtons();
		if (!firstBill){
			document.getElementById("description").focus();
		}
	}

	async function getPendingBills(fetched){
		var d;
		if (fetched !== undefined){
			localBills = [];
			if (fetched){
				showBills = false;
				d = fetched;
			} else {
				localBills = JSON.parse(localStorage.getItem($userUUID+'_pendingbills'));
			}
		} else {
			showBills = false;
			localBills = JSON.parse(localStorage.getItem($userUUID+'_pendingbills'));
			d = localBills;
		}
		if (d){
			bills = [];
			billIndexes = [];
			d = d.bills;
			for (let i=0; i<d.length; i++){
				d[i].me = {
					share: d[i].expenseMap[$userUUID] ? d[i].expenseMap[$userUUID].owes: 0,
					paid: d[i].expenseMap[$userUUID] ? d[i].expenseMap[$userUUID].paid: 0
				}
				d[i].state = d[i].state == 'created' ? 'Pending': d[i].state;
				billIndexes = [...billIndexes, d[i].uuidHash];
				bills = [...bills, d[i]];
			}
			if (d.length > 0){
				pendingbillsCheck = true;
				initWS();
			}
		}
		if (!fetched){
			unsubmittedBills = JSON.parse(localStorage.getItem($userUUID+'_unsubmittedbills')) || [];
			if (unsubmittedBills.length > 0){
				if (window.navigator.onLine){
					submitPending(true);
				} else {
					offlineCheck = window.addEventListener('online', submitPending);
				}
			}
			//setTimeout(async () => {
			var d = await makeAuthenticateCall('/bill/pending');
			if (d && d.success){
				localBills = [];
				await getPendingBills(d);
				localStorage.setItem($userUUID+'_pendingbills', JSON.stringify(d));
			} else {
				if (localBills && localBills.bills.length > 0){
					showBills = true;
				}
				localBills = [""];
			}
			//}, 3000);
		} else {
			showBills = true;
		}
	}

	async function clearGroup(disable){
		currentGroup = {name: "", members: []};
		isSetGroup = false;
		//event target gets passed from buttons
		disable = disable && !disable.target ? true : false;
		if (dummyGroups){
			groups = {};
			dummyGroups = false;
		}
		await populateGroupMembers(undefined, disable);
		await tick();
		setLabels();
		M.updateTextFields();
		if (!disable){
			document.getElementById("autocomplete-input").focus();
		}
	}

	async function populateGroupMembers(fetched, disableExpand){
		var d;
		showGroups = false;
		if (fetched !== undefined){
			if (fetched){
				d = fetched;
			} else {
				//We set null to skip loading from localStorage and force a remote fetch.
				//However, setting localgroups to fill groups in case remote call fails
				localGroups = JSON.parse(localStorage.getItem($userUUID+'_groups_members'));
			}
		} else {
			localGroups = JSON.parse(localStorage.getItem($userUUID+'_groups_members'));
			d = localGroups;
		}
		if (d && d.connections.length > 0 && !dummyGroups){
			d = d.connections;
			let data = {};
			for (let i=0; i<d.length; i++){
				data[d[i].group.name] = null;
				groups[d[i].group.name] = {
					name: d[i].group.name,
					uuid: d[i].group.uuid,
					currency: d[i].group.currency,
					members: d[i].members
				}
			}
			//If the user has set the group, don't repopulate from remote
			if (Object.keys(groups).length > 0 && !isSetGroup){
				showGroups = true;
				await tick();
				let autoCompleteElement = document.querySelector('#autocomplete-input');
				let instance = M.Autocomplete.getInstance(autoCompleteElement);
				if (instance){
					instance.updateData(data);
				} else {
					let instance = M.Autocomplete.init(autoCompleteElement, {
						data: data,
						minLength: 0,
						limit: 3,
						onAutocomplete: setGroup
					});
					if (!disableExpand){
						//we may not want to auto open autocomplete dropdown every time
						instance.open();
					}
				}
				let toolTips = document.querySelectorAll('.tooltipped');
				M.Tooltip.init(toolTips);
			}
		}
		if (!fetched){
			//setTimeout(async () => {
			d = await makeAuthenticateCall('/getconnectedusers', {});
			if (d && d.success){
				localGroups = [];
				await populateGroupMembers(d, disableExpand);
				setLabels();
				localStorage.setItem($userUUID+'_groups_members', JSON.stringify(d));
			} else {
				if (localGroups.connections && localGroups.connections.length > 0 && !showGroups){
					//Since remote failed, lets prefill localGroups if it wasn't filled in the first place;
					await populateGroupMembers(localGroups, disableExpand);
				}
				localGroups = [""];
			}
			//}, 5000);
		} else {
			showGroups = true;
			if (Object.keys(groups).length == 0 && !isSetGroup){
				if ($corporateProfileStore){
					goto('/corporate');
					return;
				}
				console.log('filling dummy groups');
				//fill dummy groups
				let data = {
					"🏡 Apartment Expenses": null,
					"💼 Work Outings": null,
					"🛄 Travel Folks": null,
				}
				if (Object.keys(dummyGroupData).length == 0){
					dummyGroupData = {
						"🏡 Apartment Expenses": {
							name: "🏡 Apartment Expenses",
							uuid: "",
							description: "Groceries",
							currency: $userCurrency,
							members: [{
								uuid: $userUUID,
								name: "You",
								email: ""
							}, {
								uuid: fakeUserUUID,
								name: "Friends @ MoneyVigil",
								email: "hello@moneyvigil.com"
							}],
						},
						"💼 Work Outings": {
							name: "💼 Work Outings",
							uuid: "",
							description: "Dinner at Hilton",
							currency: $userCurrency,
							members: [{
								uuid: $userUUID,
								name: "You",
								email: ""
							}, {
								uuid: fakeUserUUID,
								name: "Friends @ MoneyVigil",
								email: "hello@moneyvigil.com"
							}],
						},
						"🛄 Travel Folks": {
							name: "🛄 Travel Folks",
							uuid: "",
							description: "Airbnb for Europe trip",
							currency: $userCurrency,
							members: [{
								uuid: $userUUID,
								name: "You",
								email: ""
							}, {
								uuid: fakeUserUUID,
								name: "Friends @ MoneyVigil",
								email: "hello@moneyvigil.com"
							}],
						}
					};
				}
				groups = JSON.parse(JSON.stringify(dummyGroupData));
				dummyGroups = true;
				await tick();
				let autoCompleteElement = document.querySelector('#autocomplete-input');
				let instance = M.Autocomplete.getInstance(autoCompleteElement);
				if (instance){
					instance.updateData(data);
				} else {
					instance = M.Autocomplete.init(autoCompleteElement, {
						data: data,
						minLength: 0,
						onAutocomplete: setGroup
					});
				}
				//if (!disableExpand)
				{
					//we may not want to auto open autocomplete dropdown every time
					instance.open();
				}
			}
			M.updateTextFields();
			setRippleButtons();
		}
	}

	async function submitPending(auto){
		if (!auto){
			await getPendingBills(null);
		}
		let count = 0;
		let failed = 0;
		for (let i=0; i<unsubmittedBills.length; i++){
			const billData = unsubmittedBills[i];
			if (!billData){
				unsubmittedBills = [...unsubmittedBills]; //#FIXME better way to splice in Svelte?
				i--;
				continue;
			}
			let d = await makeAuthenticateCall('/bill/', billData);
			if (d.success){
				d.bill.me = {
					share: d.bill.expenseMap[$userUUID] ? d.bill.expenseMap[$userUUID].owes: 0,
					paid: d.bill.expenseMap[$userUUID] ? d.bill.expenseMap[$userUUID].paid: 0
				};
				d.bill.state = 'Pending';
				d.bill.transition = true;
				billIndexes = [...billIndexes, d.bill.uuidHash];
				bills = [...bills, d.bill];
				initWS();
				count++;
				unsubmittedBills.splice(i, 1);
				unsubmittedBills = [...unsubmittedBills]; //#FIXME better way to splice in Svelte?
				i--;
			} else {
				failed++;
				unsubmittedBills[i].failedCount++;
				await delay(2000);
				//#FIXME What do we do about pending bills that keep failing?
			}
		}
		if (count > 0){
			M.toast({html: 'Added '+count+' offline bill'+(count == 1 ? '' : 's')+'! Waiting for Blockchain confirmation.'});
		}
		if (failed > 0){
			M.toast({html: 'We could not submit '+failed+' offline bill'+(failed == 1 ? '' : 's')+'! Will try again later.'});
		}
		localStorage.setItem($userUUID+'_unsubmittedbills', JSON.stringify(unsubmittedBills));
	}

	function delay(ms) {
		return new Promise(function (resolve) { return setTimeout(resolve, ms); });
	};
</script>
<svelte:head>
	<title>Home </title>
</svelte:head>

{#if $loginModalStore}
	<Login/>
{/if}
{#if showGroupModal}
	<Group groupName={validEmail ? 'Group with '+(isUser.name || currentGroup.name.split('@')[0]) : currentGroup.name.split('@')[0]} email={validEmail ? currentGroup.name : ''} uuid={currentGroup.uuid} on:close="{(g) => {
		if (g.detail){
			(async(g) => {
				await populateGroupMembers();
				showGroupModal = false;
				setGroup(g.detail);
			})(g);
		} else {
			showGroupModal = false;
		}
	}}" />
{/if}
<div id="hometab" class="col s12">
	<div class="row">
		{#if !dummyGroups}
		<div class="col s12">
			{#if currentBill.uuid}
			<h4>Update Bill</h4>
			{:else}
			<h4>Dashboard</h4>
			{/if}
		</div>
		{/if}
	</div>
	<form>
	{#if !isSetGroup}
	<div class="row">
		{#if showGroups}
			{#if dummyGroups}
			<div class="card-panel">
				<h5>
					All MoneyVigil expenses are clubbed into groups. We've created a few to get you started👇
				</h5>
			</div>
			{/if}
			{#if Object.keys(groups).length > 0}
			<div class="input-field col s12 m7">
				<input type="text" id="autocomplete-input" bind:value={currentGroup.name} class="autocomplete" placeholder={$corporateProfileStore ? "Start typing": "Apartment expenses, Work Outings, etc"} autocomplete="new-password">
				<label for="autocomplete-input">{$corporateProfileStore ? 'Search entities to file expenses with' : 'Search groups/friends to split with'}</label>
				{#if localGroups.length > 0}<span class="helper-text red-text">Using offline data for groups</span>{/if}
				{#if currentGroup.name && !isSetGroup}
					<span class="helper-text">
					{#if isUser.name}Found {isUser.name}!
					{:else if validEmail}
						{#if isUser.checking}Checking..
						{:else}{currentGroup.name.split('@')[0]} will be invited!
						{/if}
					{:else}
					You can enter an email to invite friends
					{/if}
					</span>
				{/if}
			</div>
				{#if !$corporateProfileStore}
				<div class="input-field col s12 m5">
					<button type="button" class="mdc-button mdc-button--raised" on:click={()=> {showGroupModal = true;}}>Create New Group {validEmail ? 'with '+(isUser.name || currentGroup.name.split('@')[0]) : currentGroup.name.split('@')[0]}
					</button>
				</div>
				{/if}
			{/if}
		{:else if localGroups && localGroups.length > 0}
			<div class="col s12">We could not fetch groups. Try again later.</div>
		{/if}
	</div>
	{:else}
		{#if currentBill.uuid}
		<div class="row">
			<div class="col s12">
			Bill: <div class="chip"><span>{currentBill.uuid}</span></div>
			</div>
		</div>
		{:else}
		<div class="row">
			<div class="col s12">
			Group: <div class="chip"><span>{currentGroup.name}</span><a href="#!" on:click={clearGroup} style="cursor: pointer;"><i class="close material-icons">close</i></a></div>
			</div>
		</div>
		{/if}
	{/if}
	<div class="row" style={isSetGroup ? "margin-bottom: 0 !important": "display:none"}>
		<div class="file-field input-field col s12">
			<div class="mdc-button mdc-button--raised col s6 m3">
				<i class="material-icons mdc-button__icon right">cloud_upload</i>
				<span class="mdc-button__label loading">{#if uploading}{#if uploadingPercentage > 0 && uploadingPercentage <100}{uploadingPercentage}% uploaded{:else}Scanning<span>.</span><span>.</span><span>.</span>{/if}{:else}{fileHash ? 'Change' : 'Scan'} Receipt{/if}</span>
				<input type="file" id="receipt" on:change={checkFile}>
			</div>
			<div class="file-path-wrapper">
				<input class="file-path" bind:value={uploadedFileName} type="text" placeholder="Upload from camera" disabled>
			</div>
			{#if uploadingPercentage > 0 && uploadingPercentage <100}
			<div class="progress" style="position: relative;">
				<div class="determinate" style="width: {uploadingPercentage}%"></div>
			</div>
			{/if}
			<img id="preview" style="display:{uploadedFileName ? 'block' : 'none'}; max-height:200px;" />
			<img id="nopreview" style="display:none" />
			<canvas id="canvas" style="display:none;"></canvas>
			<span class="helper-text">{#if fileHash}Attached Receipt{:else}We will try to find information from the bill{/if}</span>
		</div>

		<div class="input-field col s12 m12" style={descriptionFocused ? "": "margin-bottom: 0"}>
			<input id="description" placeholder="Dinner at Hard Rock Cafe with College folks" type="text" on:focus={() => {descriptionFocused = true;}} on:blur={() => {descriptionFocused = false;}} bind:value={description} class="validate" autocomplete="moneyvigil-description" required>
			<label for="description">What is it for?</label>
			<span class="helper-text">{#if description && descriptionFocused}Enter a description for the bill such as Rent, Dinner, Date{/if}</span>
		</div>
		<div class="input-field col s12 m5">
			<input id="date" type="text" class="datepicker">
			<label for="date">Paid on</label>
		</div>
		<div class="input-field col s7 m3">
			<input id="amount" bind:value={totalAmount} type="number" step="any" min="0" max="999999999999" class="validate" required>
			<label for="amount">Total Amount</label>
			<span class="helper-text">{isSetGroup && totalAmount > 0 ? getFormattedMoney(totalAmount, currentGroup.currency) : ''}</span>
		</div>
		{#if isSetGroup && currentGroup.members.length > 1 && !$corporateProfileStore}
		<div class="input-field col s5 m3">
		{#if !owesAmountLocked}
			<button type="button" class="mdc-button mdc-button--raised tooltipped" id="splitButton"  on:click={doSplit} data-position="right" data-tooltip="Auto Splitting">
				<span class="mdc-button__label">Split</span>
				<i class="material-icons mdc-button__icon right">autorenew</i>
			</button>
		{:else}
			<button type="button" class="mdc-button mdc-button--raised tooltipped" id="splitButton" on:click={doSplit} data-position="right" data-tooltip="Turn on Auto Splitting">
				<span class="mdc-button__label">Split</span>
				<i class="material-icons mdc-button__icon right">call_split</i>
			</button>
		{/if}
		</div>
		{/if}
	</div>
	{#if isSetGroup}
	<div class="row">
		{#if currentGroup.members.length > 1 && !$corporateProfileStore}
		<div class="col s12">
			<table class="striped" id="friends">
				<thead>
					<tr>
						<th>
						<button type="button" class="mdc-button mdc-button--outlined tooltipped" data-position="right" data-intercom-target="Add Member" data-tooltip="Add a new member" on:click={() => {showGroupModal = true;}}>
							<i class="material-icons mdc-button__icon">add</i>
							<span class="mdc-button__label">Add</span>
						</button>
						</th>
						<th>Share{#if checkOwesAmount !=totalAmount}&nbsp;<span class="red-text">(Diff: {Number((totalAmount-checkOwesAmount).toFixed(2))})</span>{/if}</th>
						<th>Paid{#if checkPaidAmount !=totalAmount}&nbsp;<span class="red-text">(Diff: {Number((totalAmount-checkPaidAmount).toFixed(2))})</span>{/if}</th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td><strong>You</strong></td>
						<td>
								<input name="owes{$userUUID}" bind:value={owesAmount} class="validate" type="number" step="any" min="0" max="999999999999">
						</td>
						<td>
								<input name="paid{$userUUID}" bind:value={paidAmount} class="validate" type="number" step="any" min="0" max="999999999999">
						</td>
						<td>
							<!--
							<div class="input-field col s12">
								<a href='#!' on:click={removeFriend} style="cursor: pointer;"><i class="material-icons left">clear</i></a>
							</div>
							-->
						</td>
					</tr>
					{#each Object.values(currentGroup.members) as member}
					{#if member.uuid != $userUUID}
					<tr>
						<td style="max-width: 156px">
							{member.name} <span class="truncate" title={member.email}>({member.email})</span>
						</td>
						<td>
								<input name="owes{member.uuid}" bind:value={member.owes} class="validate" type="number" step="any" min="0" max="999999999999">
						</td>
						<td>
								<input name="paid{member.uuid}" class="validate" bind:value={member.paid} type="number" step="any" min="0" max="999999999999">
						</td>
						<td>
							<button type="button" class="mdc-button mdc-icon-button" on:click={() => {removeFriend(member.uuid)}} style="min-width: 30px; margin: 0; padding: 0">
							<i class="material-icons mdc-button__icon">clear</i>
							</button>
						</td>
					</tr>
					{/if}
					{/each}
				</tbody>
			</table>
		</div>
		{/if}
		<div class="input-field col s12">
			{#if submitEnabled && !submitting}
			<button type="submit" class="mdc-button mdc-button--raised" data-intercom-target="Submit Bill" on:click={submitBill}>
				<span class="mdc-button__label">{currentBill.uuid ? 'Update' : (fileHash ? 'Upload' : 'Submit')} Bill</span>
				<i class="material-icons mdc-button__icon right">send</i>
			</button>
			{:else}
				{#if !submitting}
				<span class="helper-text red-text">
					{#if !descriptionFocused}Required: {description ? '' : ' Description'}{totalAmount == 0 || checkOwesAmount != totalAmount || checkPaidAmount != totalAmount ? (description ? '' : ' and' )+' Total' : ''}
					{/if}
				</span>
				{/if}
			<button type="submit" class="mdc-button mdc-button--raised" disabled>
				<span class="mdc-button__label loading">
				{#if submitting}{currentBill.uuid ? 'Updating' : (fileHash ? 'Uploading' : 'Submitting')}<span>.</span><span>.</span><span>.</span>{:else}{currentBill.uuid ? 'Update' : (fileHash ? 'Upload' : 'Submit')} Bill{/if}
				</span>
				{#if !submitting}<i class="material-icons mdc-button__icon right">send</i>{/if}
			</button>
			{/if}
		</div>
		{#if firstBill}
		<div class="card-panel col s12">
			<h5>
				👆 Go ahead and add your first bill.
			</h5>
		</div>
		{/if}
		<div class="input-field col s12" style="margin-top: 0">
			<span class="helper-text">We only store encrypted proofs on Blockchain, your personal data is never stored publicly.</span>
		</div>
	</div>
	{/if}
	</form>
	{#if unsubmittedBills.length > 0}
	<h4>Offline Bills</h4>
	<div class="row">
		<table id="bills" class="striped">
		<thead>
			<tr>
				<th>Description</th><th>Amount</th><th>Share</th><th>Paid</th>
			</tr>
		</thead>
		<tbody>
		{#each unsubmittedBills as bill}
			{#if bill}
			<tr transition:fade>
				<td>{bill.description}</td>
				<td>{bill.totalAmount/100}</td>
				<td>{bill.me.share/100}</td>
				<td>{bill.me.paid/100}</td>
			</tr>
			{/if}
		{/each}
		</tbody>
		</table>
	</div>
	{/if}
	{#if (showBills && bills.length > 0) }
	<h4>Pending Bills</h4>
	{/if}
	{#if showBills && localBills.length > 0}
	<span class="helper-text red-text">Using offline data for bills</span>
	{/if}
	<div class="row">
		<div class="col s12">
	{#if showBills}
		{#if bills.length > 0}
			<table id="bills" class="striped">
				<thead>
					<tr>
						<th>Description</th><th>Amount</th><th class="right">Status</th>
					</tr>
				</thead>
				<tbody>
				{#each bills as bill}
					{#if bill.uuid}
						<tr transition:fade>
							<td style="max-width: 130px"><span class="truncate">{bill.metadata.description}</span></td>
							<td>{bill.metadata.totalAmount/100}</td>
							<td class="right">
							<button type="button" class="mdc-button mdc-button--outlined" disabled>
								{bill.state}
							</button>
							</td>
						</tr>
					{:else}
						<tr></tr>
					{/if}
				{/each}
				</tbody>
			</table>
		{:else if pendingbillsCheck}
		All pending bills synced!
		{/if}
	{:else if localBills && localBills.length > 0}
		<div style="display:none;">We could not fetch pending bills. Try again later.</div>
	{:else}
		<div style="display:none;">Fetching pending bills..</div>
	{/if}
		</div>
	</div>
</div>
