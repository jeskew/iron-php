install-test-deps:
	cd tests && npm install

test:
	vendor/bin/phpunit
