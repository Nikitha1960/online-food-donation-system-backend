const Fund = require("../../models/fund.model");
const FundDonation = require("../../models/fundDonation.model");

const donateToFund = async (req, res) => {
  try {
    const fundID = req.params.id;
    const { userID, amount, organizationID } = req.body;
    const newFund = new FundDonation({
      userID,
      fundID,
      amount,
      organizationID
    });

    newFund.save()
      .then(async () => {
        await Fund.findById(fundID)
          .then(async (fund) => {
            // var previousAmount = fund.currentAmount;
            var newAmount = parseInt(amount) + fund.currentAmount;
            var updateFund = {}
            if (newAmount === fund.budget) {
              updateFund = {
                currentAmount: newAmount,
                status: "completed"
              };
            } else {
              updateFund = {
                currentAmount: newAmount,
              };
            }
            await Fund.findByIdAndUpdate(fundID, updateFund)
              .then(() => {
                res.status(201).json({
                  message: "Donated successfully",
                });
              })
              .catch((err) => {
                res.status(500).json({
                  message: err,
                });
              });
          })
          .catch((err) => {
            res.status(500).json({
              message: err,
            });
          });
      })
      .catch((err) => {
        res.status(500).json({
          message: err,
        });
      });
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  donateToFund,
};
