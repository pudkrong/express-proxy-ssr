exports.test = async (req, res) => {
  res.json({ hello: req.user.firstname });
}