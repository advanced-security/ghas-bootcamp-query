/**
 * @name Missing JWT signature method validation
 * @description When parsing a JWT token the signature method must be validated to be an expected method.
 * @kind problem
 * @id go/jwt-go-signature-method-validation
 * @precision high
 * @probem.severity error
 * @tags security
 */

import go

class ParseJWTCall extends DataFlow::CallNode {
  DataFlow::Node keyFunc;

  ParseJWTCall() {
    this.getTarget().getPackage().getName() = "jwt" and
    (
      this.getCalleeName() = "ParseWithClaims" and
      this.getArgument(2) = keyFunc
      or
      this.getCalleeName() = "Parse" and this.getArgument(1) = keyFunc
    )
  }

  FuncDef getKeyFunc() {
    result = keyFunc.(DataFlow::FunctionNode).getFunction().getFuncDecl() or
    result = keyFunc.(DataFlow::FuncLitNode).asExpr().(FuncLit)
  }
}

class TypeCastResultCheck extends ControlFlow::ConditionGuardNode {
  DataFlow::TypeCastNode tc;
  DataFlow::ReadNode r;

  TypeCastResultCheck() {
    getATypeCastResultRead(tc, r) and
    (
      this.getCondition().getAChildExpr() = r.asExpr()
      or
      this.getCondition() = r.asExpr()
    )
  }

  DataFlow::TypeCastNode getTypeCast() { result = tc }

  DataFlow::ReadNode getResultRead() { result = r }
}

predicate getATypeCastResultRead(DataFlow::TypeCastNode n, DataFlow::ReadNode r) {
  exists(DefineStmt s, Variable ok |
    s.getLhs(1).(VariableName).getTarget() = ok and
    s.getRhs() = n.asExpr() and
    ok.getARead() = r
  )
}

class JwtToken extends Type {
  JwtToken() { this.getQualifiedName() = "github.com/dgrijalva/jwt-go.Token" }

  DataFlow::FieldReadNode getAMethodRead() { result = this.getField("Method").getARead() }
}

class MethodValidation extends TypeCastResultCheck {
  MethodValidation() {
    this.ensures(getResultRead(), false) and
    exists(ReturnStmt retNil | retNil.getExpr(0) = Builtin::nil().getAReference() |
      this.dominatesNode(retNil.getFirstControlFlowNode())
    )
  }

  DataFlow::ReadNode getAValidatedToken() {
    exists(JwtToken t, DataFlow::FieldReadNode fr |
      tc.getOperand() = fr and
      fr = t.getAMethodRead() and
      result = fr.getBase().(DataFlow::PointerDereferenceNode).getOperand()
    )
  }
}

class SigningMethodHMAC extends Type {
  SigningMethodHMAC() { this.getQualifiedName() = "github.com/dgrijalva/jwt-go.SigningMethodHMAC" }
}

class SigningMethodHMACTypeCast extends DataFlow::TypeCastNode {
  SigningMethodHMACTypeCast() {
    this.getResultType().(PointerType).getBaseType() instanceof SigningMethodHMAC
  }
}

class HmacMethodValidation extends MethodValidation {
  HmacMethodValidation() { this.getTypeCast() instanceof SigningMethodHMACTypeCast }
}

from ParseJWTCall parseJwtCall, FuncDef keyFunc, Parameter token
where
  keyFunc = parseJwtCall.getKeyFunc() and
  token = keyFunc.getAParameter() and
  not exists(HmacMethodValidation v | v.getAValidatedToken() = token.getARead())
select keyFunc, "Key validation function doesn't verify $@ signing method", token, "token"
