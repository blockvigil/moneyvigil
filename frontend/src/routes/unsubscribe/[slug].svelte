<script>
	import { onMount } from 'svelte';
	import { stores } from '@sapper/app';
	const { page } = stores();
	import { makeAuthenticateCall } from '../../common.js';

	let {slug} = $page.params;
	let waiting = true;

	onMount(async () => {
		let d = await makeAuthenticateCall('/unsubscribe', {
			token: slug
		});
		if (d.success){
			waiting = false;
		} else {
			console.error('Unknown unsubscribe token', slug);
			alert('Something went wrong! Contact hello@moneyvigil.com');
		}
	});

</script>

<svelte:head>

	<title>Unsubscribe</title>
</svelte:head>

{#if waiting}
<h3>Waiting to unsubscribe..</h3>
{:else}
<h3>You have been unsubscribed from all emails</h3>
{/if}
