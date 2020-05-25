import { tick } from 'svelte';
import { progressvar, userUUID, userToken, userCurrency, loginModalStore, wxEventStore, wsTxStore, wsBillStore } from './stores.js';
import {MDCRipple} from '@material/ripple';
import uuid from 'uuid-browser/v4';


const timestamp = process.env.SAPPER_TIMESTAMP;
let progressvar_value;

let userUUID_value;
export let userToken_value;
export let userCurrency_value;
export let apiPrefix;
export let receiptPrefix;
let wsURL;
let wsKey;
let intercomID;
export let fakeUserUUID;
let intercomShown;
let intercomTimeout;
let aclContract;
export let ensDomain;

let portis;
let provider;
let ethAccount;


apiPrefix = process.env.API_PREFIX;
receiptPrefix = process.env.RECEIPT_PREFIX;
wsURL = process.env.WS_URL;
wsKey = process.env.WS_KEY;
intercomID = process.env.INTERCOM_ID;
fakeUserUUID = process.env.FAKE_USER_UUID;
aclContract = process.env.ACL_CONTRACT;
ensDomain = process.env.ENS_DOMAIN;


export let currencyMap = {"BD": "BDT", "BE": "EUR", "BF": "XOF", "BG": "BGN", "BA": "BAM", "BB": "BBD", "WF": "XPF", "BL": "EUR", "BM": "BMD", "BN": "BND", "BO": "BOB", "BH": "BHD", "BI": "BIF", "BJ": "XOF", "BT": "BTN", "JM": "JMD", "BV": "NOK", "BW": "BWP", "WS": "WST", "BQ": "USD", "BR": "BRL", "BS": "BSD", "JE": "GBP", "BY": "BYR", "BZ": "BZD", "RU": "RUB", "RW": "RWF", "RS": "RSD", "TL": "USD", "RE": "EUR", "TM": "TMT", "TJ": "TJS", "RO": "RON", "TK": "NZD", "GW": "XOF", "GU": "USD", "GT": "GTQ", "GS": "GBP", "GR": "EUR", "GQ": "XAF", "GP": "EUR", "JP": "JPY", "GY": "GYD", "GG": "GBP", "GF": "EUR", "GE": "GEL", "GD": "XCD", "GB": "GBP", "GA": "XAF", "SV": "USD", "GN": "GNF", "GM": "GMD", "GL": "DKK", "GI": "GIP", "GH": "GHS", "OM": "OMR", "TN": "TND", "JO": "JOD", "HR": "HRK", "HT": "HTG", "HU": "HUF", "HK": "HKD", "HN": "HNL", "HM": "AUD", "VE": "VEF", "PR": "USD", "PS": "ILS", "PW": "USD", "PT": "EUR", "SJ": "NOK", "PY": "PYG", "IQ": "IQD", "PA": "PAB", "PF": "XPF", "PG": "PGK", "PE": "PEN", "PK": "PKR", "PH": "PHP", "PN": "NZD", "PL": "PLN", "PM": "EUR", "ZM": "ZMK", "EH": "MAD", "EE": "EUR", "EG": "EGP", "ZA": "ZAR", "EC": "USD", "IT": "EUR", "VN": "VND", "SB": "SBD", "ET": "ETB", "SO": "SOS", "ZW": "ZWL", "SA": "SAR", "ES": "EUR", "ER": "ERN", "ME": "EUR", "MD": "MDL", "MG": "MGA", "MF": "EUR", "MA": "MAD", "MC": "EUR", "UZ": "UZS", "MM": "MMK", "ML": "XOF", "MO": "MOP", "MN": "MNT", "MH": "USD", "MK": "MKD", "MU": "MUR", "MT": "EUR", "MW": "MWK", "MV": "MVR", "MQ": "EUR", "MP": "USD", "MS": "XCD", "MR": "MRO", "IM": "GBP", "UG": "UGX", "TZ": "TZS", "MY": "MYR", "MX": "MXN", "IL": "ILS", "FR": "EUR", "IO": "USD", "SH": "SHP", "FI": "EUR", "FJ": "FJD", "FK": "FKP", "FM": "USD", "FO": "DKK", "NI": "NIO", "NL": "EUR", "NO": "NOK", "NA": "NAD", "VU": "VUV", "NC": "XPF", "NE": "XOF", "NF": "AUD", "NG": "NGN", "NZ": "NZD", "NP": "NPR", "NR": "AUD", "NU": "NZD", "CK": "NZD", "XK": "EUR", "CI": "XOF", "CH": "CHF", "CO": "COP", "CN": "CNY", "CM": "XAF", "CL": "CLP", "CC": "AUD", "CA": "CAD", "CG": "XAF", "CF": "XAF", "CD": "CDF", "CZ": "CZK", "CY": "EUR", "CX": "AUD", "CR": "CRC", "CW": "ANG", "CV": "CVE", "CU": "CUP", "SZ": "SZL", "SY": "SYP", "SX": "ANG", "KG": "KGS", "KE": "KES", "SS": "SSP", "SR": "SRD", "KI": "AUD", "KH": "KHR", "KN": "XCD", "KM": "KMF", "ST": "STD", "SK": "EUR", "KR": "KRW", "SI": "EUR", "KP": "KPW", "KW": "KWD", "SN": "XOF", "SM": "EUR", "SL": "SLL", "SC": "SCR", "KZ": "KZT", "KY": "KYD", "SG": "SGD", "SE": "SEK", "SD": "SDG", "DO": "DOP", "DM": "XCD", "DJ": "DJF", "DK": "DKK", "VG": "USD", "DE": "EUR", "YE": "YER", "DZ": "DZD", "US": "USD", "UY": "UYU", "YT": "EUR", "UM": "USD", "LB": "LBP", "LC": "XCD", "LA": "LAK", "TV": "AUD", "TW": "TWD", "TT": "TTD", "TR": "TRY", "LK": "LKR", "LI": "CHF", "LV": "EUR", "TO": "TOP", "LT": "LTL", "LU": "EUR", "LR": "LRD", "LS": "LSL", "TH": "THB", "TF": "EUR", "TG": "XOF", "TD": "XAF", "TC": "USD", "LY": "LYD", "VA": "EUR", "VC": "XCD", "AE": "AED", "AD": "EUR", "AG": "XCD", "AF": "AFN", "AI": "XCD", "VI": "USD", "IS": "ISK", "IR": "IRR", "AM": "AMD", "AL": "ALL", "AO": "AOA", "AQ": "", "AS": "USD", "AR": "ARS", "AU": "AUD", "AT": "EUR", "AW": "AWG", "IN": "INR", "AX": "EUR", "AZ": "AZN", "IE": "EUR", "ID": "IDR", "UA": "UAH", "QA": "QAR", "MZ": "MZN"};

function handleMessage(evt){
	//window.console.log('got message', evt.data);
	if (evt.data.type && evt.data.type == 'refresh'){
		if (evt.data.timestamp == timestamp){
			window.console.warn('service worker got installed after reload, not refreshing');
			return;
		}
		var toastHTML = '<span>New Version detected. <button class="btn-flat toast-action" onclick=javascript:window.location.reload();>Reload</button></span>';
		try {
			M.toast({
				html: toastHTML,
				displayLength: 30000,
				completeCallback: function(){
					window.location.reload();
				}
			});
		}
		catch (e){
			console.error(e);
			//window.location.reload();
		}
	}
}

export async function initialize(){
	if (isLoggedIn() && !userCurrency_value){
		window.addEventListener('message', handleMessage, false);
		var d = await makeAuthenticateCall('/user/');
		if (d.success){
			d.user.HTTP_CF_IPCOUNTRY = d.user.HTTP_CF_IPCOUNTRY || 'IN'; //defaults to India
			userCurrency.set(currencyMap[d.user.HTTP_CF_IPCOUNTRY]);
			try{
				/*
				Intercom('boot', {
					app_id: intercomID,
					email: d.user.email,
					name: d.user.name,
					user_id: d.user.uuid,
					user_hash: d.user.intercomHash
				});
				intercomShown = true;
				window.onscroll = () => {
					clearTimeout(intercomTimeout);
					intercomTimeout = setTimeout(() => {
						//only show intercom when scrolled to bottom
						if ((window.innerHeight + window.scrollY) >= document.body.offsetHeight) {
							Intercom('update', {"hide_default_launcher": false});
							intercomShown = true;
						}
					}, 3000);
					if (intercomShown){
						Intercom('update', {"hide_default_launcher": true});
						intercomShown = false;
					}
				};
				*/
				FS.identify(d.user.uuid, {
					email: ld.user.email,
				});
			}
			catch (e){
				//Fullstory or Intercom may be blocked, respect the user's privacy..
			}
		} else {
			window.console.error('Userinfo call failed');
			userCurrency.set('INR'); //defaults to INR
		}
	}
	await tick();
	const tabs = document.querySelector('.tabs');
	const sidenav = document.querySelectorAll('.sidenav');
	M.Sidenav.init(sidenav);
	M.Tabs.init(tabs);
	setLabels();
	M.updateTextFields();
	setRippleButtons();
}

export async function setRippleButtons(){
	await tick();
	const ripple = [].map.call(document.querySelectorAll('.mdc-button:not(.mdc-ripple-upgraded):not(:disabled)'), function(el) {
		return new MDCRipple(el);
	});
}

export async function setLabels(){
	await tick();
	const labels = document.getElementsByTagName('label');
	for (let i=0; i<labels.length; i++){
		labels[i].style.display = 'block';
	}

}

export async function setToolTips(){
	await tick();
	var elems = document.querySelectorAll('.tooltipped');
	var instances = M.Tooltip.init(elems);
}

export function checkStatus(res) {
	if (res.ok) { // res.status >= 200 && res.status < 300
		return res;
	} else {
		throw res;
	}
}

export function getFormattedMoney(number, currency){
	return new Intl.NumberFormat(navigator.language || 'en-US', { style: 'currency', currency: currency }).format(number);
}

export async function checkUser(email){
	var d = await makeAuthenticateCall('/getuser', {email: email}, '', true);
	if (d.http_status){
		alert('We are having trouble getting user info.');
	}
	if (d && d.success){
		return d.user;
	} else {
		return {'error': d.http_status};
	}
}

export async function makeAuthenticateCall(url, body, message, disableProgress, forceTimeout, formdata, type){
	if (!disableProgress)
	{
		showProgress();
	}
	let data;
	let headers = {
		'Auth-Token': userToken_value
	};
	if (!formdata){
		headers['Content-Type'] = 'application/json';
	}
	const controller = new AbortController();
	const timeout = setTimeout(
		() => { controller.abort(); },
		forceTimeout || 10000,
	);
	try {
		data = await fetch(apiPrefix+url, {
			method: type ? type : (formdata || body ? 'post' : 'get'),
			body: formdata ? body : JSON.stringify(body),
			headers: headers,
			signal: controller.signal
		}).then(checkStatus).then(r => r.json());
		clearTimeout(timeout);
	}
	catch (e){
		window.console.error(e);
		if (e.status == 401 && url != '/login'){
			localStorage.removeItem('uuid');
			localStorage.removeItem(userUUID_value+'_token');
			userUUID.set('');
			userToken.set('');
			setLoginModal(true);
			await setLabels();
		} else {
			if (message){
				alert(message);
			}
		}
		data = {"http_status": e.status || 504}
	}
	hideProgress();
	return data;
}

export async function checkPassword(password){
	if (await hibpCheck(password)){
		return 'This password is vulnerable! We suggest picking a different one!';
	} else {
		//#FIXME Needs something better, tiny strenth imported way too much data
		if (/^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})/.test(password)){
			if (/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/.test(password)){
				return 'Nice, that is a strong password!'
			}
			else {
				return '';
			}
		} else {
			return 'We suggest entering a stronger password';
		}
	}
}

export function isLoggedIn(){
	if (userUUID_value){
		return userUUID_value+'_quick';
	}
	else {
		userUUID.set(localStorage.getItem('uuid') || '');
		if (userUUID_value == ''){
			setLoginModal(true);
			return '';
		}
		userToken.set(localStorage.getItem(userUUID_value+'_token') || '');
		return userUUID_value+'_local';
	}
}

export async function checkMetaMask(returnAccount){
	var accounts;
	window.console.log('checking metamask');
	if (typeof ethereum === 'undefined') {
		if (!ethAccount){
			M.toast({html: 'Loading portis...', displayLength: 5000});
		}
		if (!portis){
			portis = new Portis('41cd595c-dda9-44a7-9118-4c49ad5e74e3', 'goerli');
			provider = new ethers.providers.Web3Provider(portis.provider);
		}
		accounts = await provider.listAccounts();
	} else {
		setTimeout(() => {
			if (!ethAccount){
				M.toast({html: 'Check your metamask!'});
			}
		}, 1000);
		try {
			accounts = await ethereum.enable()
		}
		catch (e){
			//alert('You need to give access');
			return false;
		}
	}
	ethAccount = accounts[0];
	//window.console.log('got access', accounts);
	return returnAccount ? accounts[0].toLowerCase() : true;
}

export async function personalSign(str){
	let p;
	var from = await checkMetaMask(true);
	if (portis){
		p = provider.provider;
	} else {
		p = web3.currentProvider;
	}
	var params = [ethers.utils.hexlify(ethers.utils.toUtf8Bytes(str)), from];
	var method = 'personal_sign';

	var result;
	try {
		console.log(provider);
		if (portis){
			//M.toast({html: 'Check portis...', displayLength: 3000});
		} else {
			M.toast({html: 'Check Metamask...', displayLength: 3000});
		}
		result = await new Promise((resolve, reject) => {
			p.sendAsync({
				method,
				params,
				from,
			}, function (err, result) {
				if (err) return reject(err)
				if (result.error) return reject(result.error)
				return resolve(result);
			});
		});
	}
	catch (e){
		window.console.error(e);
		alert('Sign please?')
		return false;
	}
	window.console.log('result', result);
	return result.result;
}

export async function signMessage(data){
	let chainId;
	if (portis){
		chainId = await provider.getNetwork();
		chainId = chainId.chainId;
	} else {
		chainId = web3.version.network;
	}
	if (chainId != 5){
		alert('Please switch to Goerli network!');
		return false;
	}
	window.console.log('got chainId', chainId);
	let msgParams = {
		types:{
			EIP712Domain:[
				{name:"name",type:"string"},
				{name:"version",type:"string"},
				{name:"chainId",type:"uint256"},
				{name:"verifyingContract",type:"address"}
			],
			MessageEntity: [
				{name:"actionType",type:"string"},
				{name:"group",type:"address"},
				{name:"member",type:"address"},
				{name:"amount",type:"uint256"},
				{name:"bill",type:"string"},
				//{name:"metadataHash",type:"string"},
				{name:"timestamp",type:"uint256"}
			]
		},
		primaryType: "MessageEntity",
		domain:{
			name:"ACLDispatcher",
			version:"1",
			chainId: parseInt(chainId),
			verifyingContract: "0x8c1eD7e19abAa9f23c476dA86Dc1577F1Ef401f5"
		}
	};
	var from = await checkMetaMask(true)
	if (!data){
		data = {type: ""};
	}

	switch (data.type){
		case 'Disbursal':
			msgParams.message = {
				actionType: "Disbursal",
				group: data.group,
				member: data.member,
				amount: parseInt(data.amount),
				bill: data.bill,
				timestamp: +new Date()
			}
		break;
		case 'Approval':
			msgParams.message = {
				actionType: "Approval",
				group: data.group,
				member: data.member,
				amount: parseInt(data.amount),
				bill: data.bill,
				timestamp: +new Date()
			}
		break;
		default:
			msgParams.message = {
				timestamp: +new Date()
			};
			//return false;
		break;
	}


	window.console.log('CLICKED, SENDING PERSONAL SIGN REQ', 'from', from, msgParams)
	//return false;
	var params = [from, JSON.stringify(msgParams)]
	window.console.dir(params)
	var method = 'eth_signTypedData_v3'

	if (portis){
		//M.toast({html: 'Check portis...', displayLength: 3000});
	} else {
		M.toast({html: 'Check Metamask...', displayLength: 3000});
	}
	var result;
	try {
		console.log(provider);
		result = await new Promise((resolve, reject) => {
			if (portis){
				provider.provider.sendAsync({
					method,
					params,
					from,
				}, function (err, result) {
					if (err) return reject(err)
					if (result.error) return reject(result.error)
					return resolve(result);
				});
			} else {
				web3.currentProvider.sendAsync({
					method,
					params,
					from,
				}, function (err, result) {
					if (err) return reject(err)
					if (result.error) return reject(result.error)
					return resolve(result);
				});
			}
		});
	}
	catch (e){
		window.console.error(e);
		alert('Sign please?')
		return false;
	}
	window.console.log('result', result);
	if (!data.type){
		return false;
	}
	return {
		msgParams: msgParams,
		from: from,
		result: result.result
	}
}

const unsubscribeUTOK = userToken.subscribe(value => {
	userToken_value = value;
});

const unsubscribeUID = userUUID.subscribe(value => {
	userUUID_value = value;
});

const unsubscribeCur = userCurrency.subscribe(value => {
	userCurrency_value = value;
});

const unsubscribePGV = progressvar.subscribe(value => {
	progressvar_value = value;
});

export function setLoginModal(value){
	loginModalStore.set(value);
}

export function setUserToken(value){
	userToken.set(value);
}

export function setUserId(value){
	userUUID.set(value);
}

export function showProgress(){
	progressvar.set(true);
}

export function hideProgress(){
	progressvar.set(false);
}

export function toggleProgress(){
	progressvar.set(progressvar_value == true ? false : true);
}

let wsConnection;
let wsTries = 5;
let timeout = 1000;
let wsSessionID;

export function initWS(){
	if (wsTries <= 0){
		console.error('unable to estabilish WS after 5 tries!');
		wsConnection = null;
		wsTries = 5;
		wsSessionID = null;
		return;
	}
	//Don't open a new websocket if it already exists. Figure out a better way for event filtering #FIXME
	if (wsConnection){
		return;
	}
	wsConnection = new WebSocket(wsURL);
	wsConnection.onopen = function () {
		wsConnection.send(JSON.stringify({
			'command': 'register',
			'key': wsKey
		}));
		setTimeout(heartbeat, 30000);
	};

	// Log errors
	wsConnection.onerror = function (error) {
		wsTries--;
		console.error('WebSocket Error ', error);
	};

	// Log messages from the server
	wsConnection.onmessage = function (d) {
		try {
			var data = JSON.parse(d.data);
			if (data.command){
				if (data.command == 'register:nack'){
					console.error('bad auth from WS');
					closeWS();
				}
				if (data.command == 'register:ack'){
					wsSessionID = data.sessionID;
				}
				return;
			}
			if (data.type == 'event'){
				if (data.event_data.billUUIDHash){
					wsBillStore.set({hash: data.event_data.billUUIDHash, state: data.event_name});
				} else {
					wxEventStore.set({name: data.event_name, data: data.event_data});
				}
			} else {
				//Not using this as we prefer events over transactions
				//wsTxStore.set({hash: data.txHash, status: data.status});
			}
		}
		catch (e){
			//console.error('got non json data', d.data, e);
		}
	};
	wsConnection.onclose = function(e){
		if (e.code != 1000){
			closeWS();
		} else {
			setTimeout(function(){
				initWS();
			}, timeout);
		}
	};
}

export function closeWS(){
	if (wsConnection){
		wsSessionID = null;
		wsConnection.onclose = function(){
			wsConnection = null;
		};
		wsConnection.close();
	}
}

function heartbeat() {
	if (!wsSessionID || !wsConnection || wsConnection.readyState !== 1){
		return;
	}
	wsConnection.send(JSON.stringify({
		command: "heartbeat",
		sessionID: wsSessionID
	}));
	setTimeout(heartbeat, 30000);
}

async function sha1(string){
	var sendBuffer = new TextEncoder("utf-8").encode(string);
	const buffer = await crypto.subtle.digest("SHA-1", sendBuffer);
	var hexCodes = [];
	var view = new DataView(buffer);
	for (var i = 0; i < view.byteLength; i += 4) {
		// Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
		var value = view.getUint32(i)
		// toString(16) will give the hex representation of the number without padding
		var stringValue = value.toString(16)
		// We use concatenation and slice for padding
		var padding = '00000000'
		var paddedValue = (padding + stringValue).slice(-padding.length)
		hexCodes.push(paddedValue);
	}
	// Join all the hex strings into one
	return hexCodes.join("");
}

async function hibpCheck(pwd){
	let resp, hash;
	try {
		hash = await sha1(pwd);
		resp = await fetch('https://api.pwnedpasswords.com/range/'+hash.substr(0, 5)).then(resp => resp.text());
	}
	catch (e){
		//service could be down or crypto modules unavailable
		return false;
	}
	resp = resp.split('\n');
	const hashSub = hash.slice(5).toUpperCase();
	var result = false;
	for(let index in resp){
		// Check if the line matches the rest of the hash
		if(resp[index].substring(0, 35) == hashSub){
			result = true;
			break; // If found no need to continue the loop
		}
	}
	return result;
}

async function refreshPage(checkStamp){
	console.log('got timestamp', timestamp, checkStamp);
}
