<script>
	import { onMount, tick, onDestroy } from 'svelte';
	import { createEventDispatcher } from 'svelte';
	import { setLabels, setRippleButtons } from '../common.js';
	export let disableOk = false;
	export let disableCancel = false;
	export let alwaysShow = false;
	const dispatch = createEventDispatcher();
	var modal;
	onMount(async () => {
		setLabels();
		M.updateTextFields();
		let elem = document.querySelectorAll('#modal1');
		var instances = M.Modal.init(elem, {
			dismissible: !alwaysShow,
			onCloseEnd: function(){
				document.body.style.overflow = "";
				dispatch("close");
			}
		});
		modal = instances[0];
		modal.open();
		setRippleButtons();
	});
	onDestroy(() => {
		if (modal){
			document.body.style.overflow = "";
			modal.destroy();
		}
	})
</script>

<style>
	button {
		display: block;
	}
</style>

<div id="modal1" class='modal'>
	<div class="modal-content" style={disableOk && disableCancel ? 'padding-bottom: 0px' : ''}>
		<slot name='header'></slot>
		<slot></slot>
	</div>
	{#if !disableOk || !disableCancel}
	<div class="modal-footer row">
			<div class="col s8">
				<slot name="action"></slot>
			</div>
			{#if !disableOk}
			<div class="col s8 left">
				<button class="mdc-button mdc-button--raised" on:click={() => {modal.close(); dispatch("close")}}>ok</button>
			</div>
			{/if}
			{#if !disableCancel}
			<div class="col s4">
				<button class="mdc-button right" on:click={() => {modal.close(); dispatch("close")}}>Cancel</button>
			</div>
			{/if}
	</div>
	{/if}
</div>
