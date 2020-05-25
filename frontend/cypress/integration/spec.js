describe('Sapper template app', () => {
	beforeEach(() => {
		cy.visit('/')
	});

	it('has the correct <h4>', () => {
		cy.contains('h4', 'Dashboard')
	});

	it('navigates to /settings', () => {
		cy.get('nav a').contains('Settings').click();
		cy.url().should('include', '/settings');
	});
});
