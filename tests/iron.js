var iron = require('iron'),
    password = process.argv[3],
    input = process.argv[4];

switch (process.argv[2]) {
    case 'seal':
        iron.seal(JSON.parse(input), password, iron.defaults, function (err, sealed) {
            if (err) {
                process.exit(1);
            }
            console.log(sealed);
        });
        break;
    case 'unseal':
        iron.unseal(input, password, iron.defaults, function (err, unsealed) {
            if (err) {
                process.exit(1);
            }
            console.log(JSON.stringify(unsealed));
        });
        break;
    default:
        process.exit(1);
}
