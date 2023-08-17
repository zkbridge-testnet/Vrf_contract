var registerContract = artifacts.require("Register");
var verifyContract = artifacts.require("Verify");
module.exports = function(deployer) {
    deployer.deploy(registerContract).then(function() {
        return deployer.deploy(verifyContract, registerContract.address);
    });
};