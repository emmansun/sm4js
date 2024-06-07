module.exports = function (babel) {
  const { types: t } = babel;
  return {
    name: "change-js-to-cjs",
    visitor: {
      CallExpression(path) {
        if (path.node.callee.name === "require") {
          const argument = path.node.arguments[0];
          if (t.isStringLiteral(argument)) {
            argument.value = argument.value.replace(/\.js$/, ".cjs");
          }
        }
      },
    },
  };
};
