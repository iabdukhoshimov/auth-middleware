package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

//nolint:funlen //TODO:refactor it later
func (m *authMiddleware) Auth(
	ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (
	interface{}, error,
) {
	httpPath := utils.ParseKeyFromCtx(ctx, utils.GrpcGatewayHTTPPath)
	httpMethod := utils.ParseKeyFromCtx(ctx, utils.GrpcGaewayMethod)

	newCtx := metadata.NewOutgoingContext(ctx,
		metadata.Pairs(
			utils.GrpcGatewayHTTPPath,
			httpPath,
			utils.GrpcGaewayMethod,
			httpMethod,
		),
	)

	if method, ok := m.publicEndpoints[httpPath]; ok && method == httpMethod {
		resp, errHandler := handler(newCtx, req)
		if errHandler != nil {
			return nil, grpcerrors.GetGrpcError(errHandler)
		}

		return resp, nil
	}

	accessToken := utils.ParseKeyFromCtx(ctx, utils.AuthorizationHeader)
	fields := strings.Fields(accessToken)
	if len(fields) < 2 || strings.ToLower(fields[0]) != authorizationForm {
		return nil, status.Errorf(codes.Unauthenticated, "invalid authorization header")
	}

	accessToken = fields[1]

	tokenResp, err := m.jwt.ParseToken(accessToken, jwt.AccessToken)
	if err != nil {
		zap.L().Error("failed to parse token", zap.Error(err))
		return nil, grpcerrors.GetGrpcError(grpcerrors.Error{
			RPCCode: codes.InvalidArgument,
			Code:    grpcerrors.CodeAuthTokenExpired,
			Err:     fmt.Errorf("ParseToken failed on: %v with %w", jwt.AccessToken, err),
			ErrCode: grpcerrors.ErrorCodeUnauthorized,
		})
	}

	session, err := m.authStore.SessionGetByID(ctx, tokenResp.SessionID)
	if err != nil {
		zap.L().Error("failed to get session by id", zap.Error(err))
		return nil, grpcerrors.GetGrpcError(grpcerrors.Error{
			ErrCode: grpcerrors.ErrorCodeUnauthorized,
			RPCCode: codes.Unauthenticated,
			Code:    grpcerrors.CodeSessionInvalid,
			Err:     fmt.Errorf("auth middleware.SessionsGetByID failed on: %v with %w", tokenResp.SessionID, err),
		})
	}

	if session.ExpiredAt.Time.Before(time.Now()) {
		zap.L().Error("session is expired for user: ", zap.Int64("user_id", tokenResp.ID))
		return nil, grpcerrors.GetGrpcError(grpcerrors.Error{
			RPCCode: codes.Unauthenticated,
			Code:    grpcerrors.CodeAuthTokenExpired,
			ErrCode: grpcerrors.ErrorCodeUnauthorized,
			Err:     fmt.Errorf("session is expired for user: %d", tokenResp.ID),
		})
	}

	if session.CustomerStatus.String != activatedStatus {
		zap.L().Error("user is not activated", zap.Int64("user_id", tokenResp.ID))
		return nil, grpcerrors.GetGrpcError(grpcerrors.Error{
			RPCCode: codes.InvalidArgument,
			Code:    grpcerrors.COdeCustomerBlocked,
			ErrCode: grpcerrors.ErrorCodeCustomerBlocked,
			Err:     fmt.Errorf("user with id: %d is not activated", tokenResp.ID),
		})
	}

	if !session.CustomerTwoFactorAuth.Bool {
		if method, ok := m.endpointsWithout2FA[httpPath]; ok && method == httpMethod {
			ctx = context.WithValue(ctx, config.UserID, tokenResp.ID)
			ctx = context.WithValue(ctx, config.SessionID, tokenResp.SessionID)

			return handler(ctx, req)
		}

		return nil, grpcerrors.GetGrpcError(grpcerrors.Error{
			RPCCode: codes.InvalidArgument,
			Code:    grpcerrors.Code2FANotActivated,
			ErrCode: grpcerrors.ErrorCodeUnauthorized,
			Err:     fmt.Errorf("user with id: %d is not activated 2FA device", tokenResp.ID),
		})
	}

	zap.L().Info("customer request: ",
		zap.String("path", httpPath),
		zap.String("method", httpMethod),
		zap.Int64("customer_id", tokenResp.ID),
		zap.Any("params", req),
	)
	ctx = context.WithValue(ctx, config.UserID, tokenResp.ID)
	ctx = context.WithValue(ctx, config.SessionID, tokenResp.SessionID)
	ctx = context.WithValue(ctx, config.TaxResidence, session.CustomerTaxResidenceID.Int64)
	ctx = context.WithValue(ctx, config.CountryRecidence, session.CustomerCountryResidenceID.Int64)
	ctx = metadata.NewOutgoingContext(
		ctx,
		metadata.Pairs(
			utils.AuthorizationHeader,
			"Bearer "+accessToken,
			utils.GrpcGatewayHTTPPath,
			httpPath,
			utils.GrpcGaewayMethod,
			httpMethod,
		),
	)

	return handler(ctx, req)
}
