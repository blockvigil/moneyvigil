<script>
	export let segment;
	import { onMount } from 'svelte';
	import { goto } from '@sapper/app';
	import { progressvar, corporateProfileStore } from '../stores.js';
	let progressvar_value;
	let corporateProfile = true;
	const unsubscribe = progressvar.subscribe(value => {
		progressvar_value = value;
	});
	const unsubscribeCP = corporateProfileStore.subscribe(value => {
		corporateProfile = true;
	});
	let hostname = '';
	let prevProfile = true;
	let fixedGroupUUID;
	onMount(() => {
		//corporateProfile = localStorage.getItem('corporateProfile') == 'true' || false;
		corporateProfileStore.set(corporateProfile);
		fixedGroupUUID = localStorage.getItem('fixedGroupUUID');
		prevProfile = corporateProfile;
		hostname = location.hostname;
	});
	$: {
		if (prevProfile != corporateProfile){
			prevProfile = corporateProfile
			console.log('switching...');
			localStorage.setItem('corporateProfile', corporateProfile);
			corporateProfileStore.set(corporateProfile);
			M.toast({
				html: 'Switching profile..',
				completeCallback: function(){
					location.reload();
				}
			});
			setTimeout(window.location.reload, 3000);
		}
	}
</script>
<header>
		<title>MoneyVigil</title>
			<nav class="nav-extended">
				<div class="nav-wrapper">
					<a href="./" class="brand-logo center" style="min-width: 175px;"><img alt='logo' src='/files/6-only-logo-trans-thresh-48.png' /> MoneyVigil{@html  hostname != 'alpha.moneyvigil.com' ? '<sup class="hide-on-med-and-down">DEV</sup>' : ''}</a>
					<a href="#!" data-target="mobile-demo" class="sidenav-trigger"><i class="material-icons">menu</i></a>
					<ul id="nav-mobile" class="right hide-on-med-and-down">
						<!--
						<li>
							<div class="switch">
								<label style="color:#ffffff !important;">
									Personal
									<input type="checkbox" bind:checked={corporateProfile}>
									<span class="lever"></span>
									Corporate
								</label>
							</div>
						</li>
						-->
						<li><a href="/" on:click={() => {goto('/')}}>Home</a></li>
						<li><a href="/settings">Settings</a></li>
						<li><a href="/logout" on:click={() => {goto('/logout')}}>Logout</a></li>
					</ul>
				</div>
				<div class="nav-content">
					<ul class="tabs center tabs-transparent">
						<li class="tab"><a class='{segment == 'home' ? "active" : ""}' href="/"  on:click={() => {goto('/')}}>Home</a></li>
						{#if corporateProfile}
						<li class="tab"><a class='{segment == 'groups' || segment == 'expenses' ? "active" : ""}' href="/groups"  on:click={() => {goto('/expenses')}}>Groups</a></li>
						<li class="tab"><a class='{segment == 'corporate' ? "active" : ""}' href="/corporate"  on:click={() => {goto('/corporate')}}>Entities</a></li>
						{:else}
						<li class="tab"><a class='{segment == 'groups' ? "active" : ""}' href="/groups"  on:click={() => {goto('/groups')}}>Groups</a></li>
						{/if}
					</ul>
				</div>
			</nav>
			<ul class="sidenav sidenav-close" id="mobile-demo">
				<li><a href="/" on:click={() => {goto('/')}}>Home</a></li>
				<li><a href="/settings">Settings</a></li>
				<li><a href="/logout" on:click={() => {goto('/logout')}}>Logout</a></li>
				<li>
					<div class="switch">
						<label>
							Personal
							<input type="checkbox" bind:checked={corporateProfile}>
							<span class="lever"></span>
							Corporate
						</label>
					</div>
				</li>
				{#if hostname != 'alpha.moneyvigil.com'}
				<h2>Dev</h2>
				{/if}
			</ul>
		</header>
<style>

</style>
<div class="progress" style="{progressvar_value ? '': 'display:none;'}">
	<div class="indeterminate"></div>
</div>
<div class="row" style="display:none;">
	<div class="input-field col s12">
		<div class="switch">
			<label>
				Personal
				<input type="checkbox">
				<span class="lever"></span>
				Corporate
			</label>
		</div>
	</div>
</div>
