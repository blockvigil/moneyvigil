import * as sapper from '@sapper/app';
import './main.css';
import "@material/button/dist/mdc.button.min.css";

//import 'material-design-icons/iconfont/material-icons.css';
//import 'materialize-css/dist/css/materialize.min.css';
import 'materialize-css/dist/js/materialize.min.js';

sapper.start({
	target: document.querySelector('body')
});
