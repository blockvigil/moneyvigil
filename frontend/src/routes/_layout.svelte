<script>
	import Nav from '../components/Nav.svelte';
	export let segment;
</script>

<svelte:head>
</svelte:head>

<style>

</style>

<Nav {segment}/>
<main class="container">
	<slot></slot>
</main>
<footer class="page-footer">
	<div class="footer-copyright">
		<div class="container">
			© 2020 BlockVigil | <a class="white-text" href="https://moneyvigil.com/legal/terms.html" target="_blank">Terms</a> | <a class="white-text" href="https://moneyvigil.com/legal/privacy.html" target="_blank">Privacy</a>
		</div>
	</div>
</footer>
