<script context="module">
	import { progressvar } from './stores.js';

	let progressvar_value;
	const unsubscribe = progressvar.subscribe(value => {
		progressvar_value = value;
	});

	export function showProgress(){
		progressvar.set(true);
	}

	export function hideProgress(){
		progressvar.set(false);
	}

	export function toggleProgress(){
		progressvar.set(progressvar_value == true ? false : true);
	}
</script>
