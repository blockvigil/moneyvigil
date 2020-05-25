import resolve from 'rollup-plugin-node-resolve';
import replace from 'rollup-plugin-replace';
import commonjs from 'rollup-plugin-commonjs';
import svelte from 'rollup-plugin-svelte';
import babel from 'rollup-plugin-babel';
import { terser } from 'rollup-plugin-terser';
import config from 'sapper/config/rollup.js';
import pkg from './package.json';
import strip from 'rollup-plugin-strip';

const mode = process.env.NODE_ENV;
const dev = mode === 'development';
const legacy = !!process.env.SAPPER_LEGACY_BUILD;

process.env.API_PREFIX = process.env.API_PREFIX || 'http://localhost:9000/blocksplitapi';
process.env.RECEIPT_PREFIX = process.env.RECEIPT_PREFIX || 'http://localhost:9000/blocksplitapi/receipt';
process.env.WS_URL = process.env.WS_URL || 'ws://localhost:9000/ws';
process.env.WS_KEY = process.env.WS_KEY || '1d5f1d64-11c0-4abf-9edb-db695e311508';
process.env.INTERCOM_ID = process.env.INTERCOM_ID || 'cysqi7au';
process.env.FAKE_USER_UUID = process.env.FAKE_USER_UUID || '117a11c3b-44bb-4d01-b5d3-a65da84e3fb3';
process.env.ACL_CONTRACT = process.env.ACL_CONTRACT || '0x8638bfd6404a3083639f5e45636fe9cbd0385368';
process.env.ENS_DOMAIN = process.env.ENS_DOMAIN || 'moneyvigil.eth';
process.env.SAPPER_TIMESTAMP = process.env.SAPPER_TIMESTAMP || Date.now();

const onwarn = (warning, onwarn) => (warning.code === 'CIRCULAR_DEPENDENCY' && warning.message.includes('/@sapper/'));

export default {
	client: {
		input: config.client.input(),
		output: config.client.output(),
		plugins: [
			replace({
				'process.browser': true,
				'process.env.API_PREFIX': JSON.stringify(process.env.API_PREFIX),
				'process.env.RECEIPT_PREFIX': JSON.stringify(process.env.RECEIPT_PREFIX),
				'process.env.WS_URL': JSON.stringify(process.env.WS_URL),
				'process.env.WS_KEY': JSON.stringify(process.env.WS_KEY),
				'process.env.INTERCOM_ID': JSON.stringify(process.env.INTERCOM_ID),
				'process.env.FAKE_USER_UUID': JSON.stringify(process.env.FAKE_USER_UUID),
				'process.env.ACL_CONTRACT': JSON.stringify(process.env.ACL_CONTRACT),
				'process.env.ENS_DOMAIN': JSON.stringify(process.env.ENS_DOMAIN),
				'process.env.SAPPER_TIMESTAMP': JSON.stringify(process.env.SAPPER_TIMESTAMP),
				'process.env.NODE_ENV': JSON.stringify(mode)
			}),
			svelte({
				dev,
				hydratable: true,
				emitCss: true
			}),
			resolve(),
			commonjs(),

			strip(),
			legacy && babel({
				extensions: ['.js', '.mjs', '.html', '.svelte'],
				runtimeHelpers: true,
				exclude: ['node_modules/@babel/**'],
				presets: [
					['@babel/preset-env', {
						targets: '> 0.25%, not dead'
					}]
				],
				plugins: [
					'@babel/plugin-syntax-dynamic-import',
					['@babel/plugin-transform-runtime', {
						useESModules: true
					}]
				]
			}),

			!dev && terser({
				module: true
			})
		],
		onwarn,
	},

	server: {
		input: config.server.input(),
		output: config.server.output(),
		plugins: [
			replace({
				'process.browser': false,
				'process.env.NODE_ENV': JSON.stringify(mode)
			}),
			svelte({
				generate: 'ssr',
				dev
			}),
			resolve(),
			commonjs()
		],
		external: Object.keys(pkg.dependencies).concat(
			require('module').builtinModules || Object.keys(process.binding('natives'))
		),
		onwarn,
	},

	serviceworker: {
		input: config.serviceworker.input(),
		output: config.serviceworker.output(),
		plugins: [
			resolve(),
			replace({
				'process.browser': true,
				'process.env.SAPPER_TIMESTAMP': JSON.stringify(process.env.SAPPER_TIMESTAMP),
				'process.env.NODE_ENV': JSON.stringify(mode)
			}),
			commonjs(),
			!dev && terser()
		],
		onwarn,
	}
};
