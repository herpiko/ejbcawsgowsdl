package ejbcawsgowsdl

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

// against "unused imports"
var _ time.Time
var _ xml.Name

type GenerateCryptoTokenKeys struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ generateCryptoTokenKeys"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 string `xml:"arg2,omitempty"`
}

type GenerateCryptoTokenKeysResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ generateCryptoTokenKeysResponse"`
}

type ErrorCode struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ errorCode"`

	InternalErrorCode string `xml:"internalErrorCode,omitempty"`
}

type CvcRequest struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ cvcRequest"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 string `xml:"arg2,omitempty"`
}

type CvcRequestResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ cvcRequestResponse"`

	Return_ []*Certificate `xml:"return,omitempty"`
}

type Certificate struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ certificate"`

	*TokenCertificateResponseWS

	CertificateData []byte `xml:"certificateData,omitempty"`
}

type TokenCertificateResponseWS struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ tokenCertificateResponseWS"`

	Certificate *Certificate `xml:"certificate,omitempty"`
	KeyStore    *KeyStore    `xml:"keyStore,omitempty"`
	Type_       int32        `xml:"type,omitempty"`
}

type KeyStore struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ keyStore"`

	*TokenCertificateResponseWS

	KeystoreData []byte `xml:"keystoreData,omitempty"`
}

type DeleteUserDataFromSource struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ deleteUserDataFromSource"`

	Arg0 []string `xml:"arg0,omitempty"`
	Arg1 string   `xml:"arg1,omitempty"`
	Arg2 bool     `xml:"arg2,omitempty"`
}

type DeleteUserDataFromSourceResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ deleteUserDataFromSourceResponse"`

	Return_ bool `xml:"return,omitempty"`
}

type KeyRecover struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ keyRecover"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 string `xml:"arg2,omitempty"`
}

type KeyRecoverResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ keyRecoverResponse"`
}

type CaRenewCertRequest struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ caRenewCertRequest"`

	Arg0 string   `xml:"arg0,omitempty"`
	Arg1 [][]byte `xml:"arg1,omitempty"`
	Arg2 bool     `xml:"arg2,omitempty"`
	Arg3 bool     `xml:"arg3,omitempty"`
	Arg4 bool     `xml:"arg4,omitempty"`
	Arg5 string   `xml:"arg5,omitempty"`
}

type CaRenewCertRequestResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ caRenewCertRequestResponse"`

	Return_ []byte `xml:"return,omitempty"`
}

type AddSubjectToRole struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ addSubjectToRole"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 string `xml:"arg2,omitempty"`
	Arg3 string `xml:"arg3,omitempty"`
	Arg4 string `xml:"arg4,omitempty"`
}

type AddSubjectToRoleResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ addSubjectToRoleResponse"`
}

type RemoveSubjectFromRole struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ removeSubjectFromRole"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 string `xml:"arg2,omitempty"`
	Arg3 string `xml:"arg3,omitempty"`
	Arg4 string `xml:"arg4,omitempty"`
}

type RemoveSubjectFromRoleResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ removeSubjectFromRoleResponse"`
}

type RevokeCert struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ revokeCert"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 int32  `xml:"arg2,omitempty"`
}

type RevokeCertResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ revokeCertResponse"`
}

type CreateCA struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ createCA"`

	Arg0 string          `xml:"arg0,omitempty"`
	Arg1 string          `xml:"arg1,omitempty"`
	Arg2 string          `xml:"arg2,omitempty"`
	Arg3 int64           `xml:"arg3,omitempty"`
	Arg4 string          `xml:"arg4,omitempty"`
	Arg5 string          `xml:"arg5,omitempty"`
	Arg6 int32           `xml:"arg6,omitempty"`
	Arg7 string          `xml:"arg7,omitempty"`
	Arg8 []*KeyValuePair `xml:"arg8,omitempty"`
	Arg9 []*KeyValuePair `xml:"arg9,omitempty"`
}

type KeyValuePair struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ keyValuePair"`

	Key   string `xml:"key,omitempty"`
	Value string `xml:"value,omitempty"`
}

type CreateCAResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ createCAResponse"`
}

type Pkcs10Request struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ pkcs10Request"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 string `xml:"arg2,omitempty"`
	Arg3 string `xml:"arg3,omitempty"`
	Arg4 string `xml:"arg4,omitempty"`
}

type Pkcs10RequestResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ pkcs10RequestResponse"`

	Return_ *CertificateResponse `xml:"return,omitempty"`
}

type CertificateResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ certificateResponse"`

	Data         []byte `xml:"data,omitempty"`
	ResponseType string `xml:"responseType,omitempty"`
}

type GetLastCAChain struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getLastCAChain"`

	Arg0 string `xml:"arg0,omitempty"`
}

type GetLastCAChainResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getLastCAChainResponse"`

	Return_ []*Certificate `xml:"return,omitempty"`
}

type ExistsHardToken struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ existsHardToken"`

	Arg0 string `xml:"arg0,omitempty"`
}

type ExistsHardTokenResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ existsHardTokenResponse"`

	Return_ bool `xml:"return,omitempty"`
}

type GetCertificate struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getCertificate"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
}

type GetCertificateResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getCertificateResponse"`

	Return_ *Certificate `xml:"return,omitempty"`
}

type GetAvailableCertificateProfiles struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getAvailableCertificateProfiles"`

	Arg0 int32 `xml:"arg0,omitempty"`
}

type GetAvailableCertificateProfilesResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getAvailableCertificateProfilesResponse"`

	Return_ []*NameAndId `xml:"return,omitempty"`
}

type NameAndId struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ nameAndId"`

	Id   int32  `xml:"id,omitempty"`
	Name string `xml:"name,omitempty"`
}

type FindUser struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ findUser"`

	Arg0 *UserMatch `xml:"arg0,omitempty"`
}

type UserMatch struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ userMatch"`

	Matchtype  int32  `xml:"matchtype,omitempty"`
	Matchvalue string `xml:"matchvalue,omitempty"`
	Matchwith  int32  `xml:"matchwith,omitempty"`
}

type FindUserResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ findUserResponse"`

	Return_ []*UserDataVOWS `xml:"return,omitempty"`
}

type UserDataVOWS struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ userDataVOWS"`

	CaName                  string                   `xml:"caName,omitempty"`
	CardNumber              string                   `xml:"cardNumber,omitempty"`
	CertificateProfileName  string                   `xml:"certificateProfileName,omitempty"`
	CertificateSerialNumber int32                    `xml:"certificateSerialNumber,omitempty"`
	ClearPwd                bool                     `xml:"clearPwd,omitempty"`
	Email                   string                   `xml:"email,omitempty"`
	EndEntityProfileName    string                   `xml:"endEntityProfileName,omitempty"`
	EndTime                 string                   `xml:"endTime,omitempty"`
	ExtendedInformation     []*ExtendedInformationWS `xml:"extendedInformation,omitempty"`
	HardTokenIssuerName     string                   `xml:"hardTokenIssuerName,omitempty"`
	KeyRecoverable          bool                     `xml:"keyRecoverable,omitempty"`
	Password                string                   `xml:"password,omitempty"`
	SendNotification        bool                     `xml:"sendNotification,omitempty"`
	StartTime               string                   `xml:"startTime,omitempty"`
	Status                  int32                    `xml:"status,omitempty"`
	SubjectAltName          string                   `xml:"subjectAltName,omitempty"`
	SubjectDN               string                   `xml:"subjectDN,omitempty"`
	TokenType               string                   `xml:"tokenType,omitempty"`
	Username                string                   `xml:"username,omitempty"`
}

type ExtendedInformationWS struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ extendedInformationWS"`

	Name  string `xml:"name,omitempty"`
	Value string `xml:"value,omitempty"`
}

type FetchUserData struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ fetchUserData"`

	Arg0 []string `xml:"arg0,omitempty"`
	Arg1 string   `xml:"arg1,omitempty"`
}

type FetchUserDataResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ fetchUserDataResponse"`

	Return_ []*UserDataSourceVOWS `xml:"return,omitempty"`
}

type UserDataSourceVOWS struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ userDataSourceVOWS"`

	IsModifyable []int32       `xml:"isModifyable,omitempty"`
	UserDataVOWS *UserDataVOWS `xml:"userDataVOWS,omitempty"`
}

type CertificateRequest struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ certificateRequest"`

	Arg0 *UserDataVOWS `xml:"arg0,omitempty"`
	Arg1 string        `xml:"arg1,omitempty"`
	Arg2 int32         `xml:"arg2,omitempty"`
	Arg3 string        `xml:"arg3,omitempty"`
	Arg4 string        `xml:"arg4,omitempty"`
}

type CertificateRequestResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ certificateRequestResponse"`

	Return_ *CertificateResponse `xml:"return,omitempty"`
}

type RevokeToken struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ revokeToken"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 int32  `xml:"arg1,omitempty"`
}

type RevokeTokenResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ revokeTokenResponse"`
}

type CaCertResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ caCertResponse"`

	Arg0 string   `xml:"arg0,omitempty"`
	Arg1 []byte   `xml:"arg1,omitempty"`
	Arg2 [][]byte `xml:"arg2,omitempty"`
	Arg3 string   `xml:"arg3,omitempty"`
}

type CaCertResponseResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ caCertResponseResponse"`
}

type CreateCRL struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ createCRL"`

	Arg0 string `xml:"arg0,omitempty"`
}

type CreateCRLResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ createCRLResponse"`
}

type GetLastCertChain struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getLastCertChain"`

	Arg0 string `xml:"arg0,omitempty"`
}

type GetLastCertChainResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getLastCertChainResponse"`

	Return_ []*Certificate `xml:"return,omitempty"`
}

type IsApproved struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ isApproved"`

	Arg0 int32 `xml:"arg0,omitempty"`
}

type IsApprovedResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ isApprovedResponse"`

	Return_ int32 `xml:"return,omitempty"`
}

type IsAuthorized struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ isAuthorized"`

	Arg0 string `xml:"arg0,omitempty"`
}

type IsAuthorizedResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ isAuthorizedResponse"`

	Return_ bool `xml:"return,omitempty"`
}

type GetEjbcaVersion struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getEjbcaVersion"`
}

type GetEjbcaVersionResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getEjbcaVersionResponse"`

	Return_ string `xml:"return,omitempty"`
}

type GetCertificatesByExpirationTime struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getCertificatesByExpirationTime"`

	Arg0 int64 `xml:"arg0,omitempty"`
	Arg1 int32 `xml:"arg1,omitempty"`
}

type GetCertificatesByExpirationTimeResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getCertificatesByExpirationTimeResponse"`

	Return_ []*Certificate `xml:"return,omitempty"`
}

type CheckRevokationStatus struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ checkRevokationStatus"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
}

type CheckRevokationStatusResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ checkRevokationStatusResponse"`

	Return_ *RevokeStatus `xml:"return,omitempty"`
}

type RevokeStatus struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ revokeStatus"`

	CertificateSN  string    `xml:"certificateSN,omitempty"`
	IssuerDN       string    `xml:"issuerDN,omitempty"`
	Reason         int32     `xml:"reason,omitempty"`
	RevocationDate time.Time `xml:"revocationDate,omitempty"`
}

type RevokeCertBackdated struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ revokeCertBackdated"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 int32  `xml:"arg2,omitempty"`
	Arg3 string `xml:"arg3,omitempty"`
}

type RevokeCertBackdatedResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ revokeCertBackdatedResponse"`
}

type GetProfile struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getProfile"`

	Arg0 int32  `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
}

type GetProfileResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getProfileResponse"`

	Return_ []byte `xml:"return,omitempty"`
}

type GetAvailableCAsInProfile struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getAvailableCAsInProfile"`

	Arg0 int32 `xml:"arg0,omitempty"`
}

type GetAvailableCAsInProfileResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getAvailableCAsInProfileResponse"`

	Return_ []*NameAndId `xml:"return,omitempty"`
}

type GetHardTokenDatas struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getHardTokenDatas"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 bool   `xml:"arg1,omitempty"`
	Arg2 bool   `xml:"arg2,omitempty"`
}

type GetHardTokenDatasResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getHardTokenDatasResponse"`

	Return_ []*HardTokenDataWS `xml:"return,omitempty"`
}

type HardTokenDataWS struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ hardTokenDataWS"`

	Certificates         []*Certificate `xml:"certificates,omitempty"`
	Copies               []string       `xml:"copies,omitempty"`
	CopyOfSN             string         `xml:"copyOfSN,omitempty"`
	CreateTime           time.Time      `xml:"createTime,omitempty"`
	EncKeyKeyRecoverable bool           `xml:"encKeyKeyRecoverable,omitempty"`
	HardTokenSN          string         `xml:"hardTokenSN,omitempty"`
	Label                string         `xml:"label,omitempty"`
	ModifyTime           time.Time      `xml:"modifyTime,omitempty"`
	PinDatas             []*PinDataWS   `xml:"pinDatas,omitempty"`
	TokenType            int32          `xml:"tokenType,omitempty"`
}

type PinDataWS struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ pinDataWS"`

	InitialPIN string `xml:"initialPIN,omitempty"`
	PUK        string `xml:"PUK,omitempty"`
	Type_      int32  `xml:"type,omitempty"`
}

type GetCertificatesByExpirationTimeAndIssuer struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getCertificatesByExpirationTimeAndIssuer"`

	Arg0 int64  `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 int32  `xml:"arg2,omitempty"`
}

type GetCertificatesByExpirationTimeAndIssuerResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getCertificatesByExpirationTimeAndIssuerResponse"`

	Return_ []*Certificate `xml:"return,omitempty"`
}

type GetCertificatesByExpirationTimeAndType struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getCertificatesByExpirationTimeAndType"`

	Arg0 int64 `xml:"arg0,omitempty"`
	Arg1 int32 `xml:"arg1,omitempty"`
	Arg2 int32 `xml:"arg2,omitempty"`
}

type GetCertificatesByExpirationTimeAndTypeResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getCertificatesByExpirationTimeAndTypeResponse"`

	Return_ []*Certificate `xml:"return,omitempty"`
}

type CrmfRequest struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ crmfRequest"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 string `xml:"arg2,omitempty"`
	Arg3 string `xml:"arg3,omitempty"`
	Arg4 string `xml:"arg4,omitempty"`
}

type CrmfRequestResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ crmfRequestResponse"`

	Return_ *CertificateResponse `xml:"return,omitempty"`
}

type SoftTokenRequest struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ softTokenRequest"`

	Arg0 *UserDataVOWS `xml:"arg0,omitempty"`
	Arg1 string        `xml:"arg1,omitempty"`
	Arg2 string        `xml:"arg2,omitempty"`
	Arg3 string        `xml:"arg3,omitempty"`
}

type SoftTokenRequestResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ softTokenRequestResponse"`

	Return_ *KeyStore `xml:"return,omitempty"`
}

type GetHardTokenData struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getHardTokenData"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 bool   `xml:"arg1,omitempty"`
	Arg2 bool   `xml:"arg2,omitempty"`
}

type GetHardTokenDataResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getHardTokenDataResponse"`

	Return_ *HardTokenDataWS `xml:"return,omitempty"`
}

type SpkacRequest struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ spkacRequest"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 string `xml:"arg2,omitempty"`
	Arg3 string `xml:"arg3,omitempty"`
	Arg4 string `xml:"arg4,omitempty"`
}

type SpkacRequestResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ spkacRequestResponse"`

	Return_ *CertificateResponse `xml:"return,omitempty"`
}

type GetPublisherQueueLength struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getPublisherQueueLength"`

	Arg0 string `xml:"arg0,omitempty"`
}

type GetPublisherQueueLengthResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getPublisherQueueLengthResponse"`

	Return_ int32 `xml:"return,omitempty"`
}

type GenTokenCertificates struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ genTokenCertificates"`

	Arg0 *UserDataVOWS                `xml:"arg0,omitempty"`
	Arg1 []*TokenCertificateRequestWS `xml:"arg1,omitempty"`
	Arg2 *HardTokenDataWS             `xml:"arg2,omitempty"`
	Arg3 bool                         `xml:"arg3,omitempty"`
	Arg4 bool                         `xml:"arg4,omitempty"`
}

type TokenCertificateRequestWS struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ tokenCertificateRequestWS"`

	CAName                 string `xml:"CAName,omitempty"`
	CertificateProfileName string `xml:"certificateProfileName,omitempty"`
	Keyalg                 string `xml:"keyalg,omitempty"`
	Keyspec                string `xml:"keyspec,omitempty"`
	Pkcs10Data             []byte `xml:"pkcs10Data,omitempty"`
	TokenType              string `xml:"tokenType,omitempty"`
	Type_                  int32  `xml:"type,omitempty"`
	ValidityIdDays         string `xml:"validityIdDays,omitempty"`
}

type GenTokenCertificatesResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ genTokenCertificatesResponse"`

	Return_ []*TokenCertificateResponseWS `xml:"return,omitempty"`
}

type EditUser struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ editUser"`

	Arg0 *UserDataVOWS `xml:"arg0,omitempty"`
}

type EditUserResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ editUserResponse"`
}

type Pkcs12Req struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ pkcs12Req"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
	Arg2 string `xml:"arg2,omitempty"`
	Arg3 string `xml:"arg3,omitempty"`
	Arg4 string `xml:"arg4,omitempty"`
}

type Pkcs12ReqResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ pkcs12ReqResponse"`

	Return_ *KeyStore `xml:"return,omitempty"`
}

type CustomLog struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ customLog"`

	Arg0 int32        `xml:"arg0,omitempty"`
	Arg1 string       `xml:"arg1,omitempty"`
	Arg2 string       `xml:"arg2,omitempty"`
	Arg3 string       `xml:"arg3,omitempty"`
	Arg4 *Certificate `xml:"arg4,omitempty"`
	Arg5 string       `xml:"arg5,omitempty"`
}

type CustomLogResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ customLogResponse"`
}

type GetAuthorizedEndEntityProfiles struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getAuthorizedEndEntityProfiles"`
}

type GetAuthorizedEndEntityProfilesResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getAuthorizedEndEntityProfilesResponse"`

	Return_ []*NameAndId `xml:"return,omitempty"`
}

type RevokeUser struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ revokeUser"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 int32  `xml:"arg1,omitempty"`
	Arg2 bool   `xml:"arg2,omitempty"`
}

type RevokeUserResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ revokeUserResponse"`
}

type GetLatestCRL struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getLatestCRL"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 bool   `xml:"arg1,omitempty"`
}

type GetLatestCRLResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getLatestCRLResponse"`

	Return_ []byte `xml:"return,omitempty"`
}

type CreateCryptoToken struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ createCryptoToken"`

	Arg0 string          `xml:"arg0,omitempty"`
	Arg1 string          `xml:"arg1,omitempty"`
	Arg2 string          `xml:"arg2,omitempty"`
	Arg3 bool            `xml:"arg3,omitempty"`
	Arg4 []*KeyValuePair `xml:"arg4,omitempty"`
}

type CreateCryptoTokenResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ createCryptoTokenResponse"`
}

type GetAvailableCAs struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getAvailableCAs"`
}

type GetAvailableCAsResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ getAvailableCAsResponse"`

	Return_ []*NameAndId `xml:"return,omitempty"`
}

type KeyRecoverNewest struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ keyRecoverNewest"`

	Arg0 string `xml:"arg0,omitempty"`
}

type KeyRecoverNewestResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ keyRecoverNewestResponse"`
}

type RepublishCertificate struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ republishCertificate"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 string `xml:"arg1,omitempty"`
}

type RepublishCertificateResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ republishCertificateResponse"`
}

type FindCerts struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ findCerts"`

	Arg0 string `xml:"arg0,omitempty"`
	Arg1 bool   `xml:"arg1,omitempty"`
}

type FindCertsResponse struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ findCertsResponse"`

	Return_ []*Certificate `xml:"return,omitempty"`
}

type EjbcaException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ EjbcaException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type AuthorizationDeniedException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ AuthorizationDeniedException"`
}

type CADoesntExistsException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ CADoesntExistsException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type UserDoesntFullfillEndEntityProfile struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ UserDoesntFullfillEndEntityProfile"`
}

type NotFoundException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ NotFoundException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type WaitingForApprovalException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ WaitingForApprovalException"`

	ApprovalId int32 `xml:"approvalId,omitempty"`
}

type CertificateExpiredException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ CertificateExpiredException"`
}

type ApprovalException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ ApprovalException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type SignRequestException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ SignRequestException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type CesecoreException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ CesecoreException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type MultipleMatchException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ MultipleMatchException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type UserDataSourceException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ UserDataSourceException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type AlreadyRevokedException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ AlreadyRevokedException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type IllegalQueryException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ IllegalQueryException"`
}

type EndEntityProfileNotFoundException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ EndEntityProfileNotFoundException"`
}

type CAOfflineException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ CAOfflineException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type CryptoTokenOfflineException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ CryptoTokenOfflineException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type ApprovalRequestExpiredException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ ApprovalRequestExpiredException"`
}

type DateNotValidException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ DateNotValidException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type RevokeBackDateNotAllowedForProfileException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ RevokeBackDateNotAllowedForProfileException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type UnknownProfileTypeException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ UnknownProfileTypeException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type HardTokenDoesntExistsException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ HardTokenDoesntExistsException"`
}

type ApprovalRequestExecutionException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ ApprovalRequestExecutionException"`
}

type HardTokenExistsException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ HardTokenExistsException"`
}

type PublisherException struct {
	XMLName xml.Name `xml:"http://ws.protocol.core.ejbca.org/ PublisherException"`

	ErrorCode *ErrorCode `xml:"errorCode,omitempty"`
}

type EjbcaWS struct {
	client *SOAPClient
}

func NewEjbcaWS(url string, tls bool, auth *BasicAuth) *EjbcaWS {
	if url == "" {
		url = ""
	}
	client := NewSOAPClient(url, tls, auth)

	return &EjbcaWS{
		client: client,
	}
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) GenerateCryptoTokenKeys(request *GenerateCryptoTokenKeys) (*GenerateCryptoTokenKeysResponse, error) {
	response := new(GenerateCryptoTokenKeysResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - CertificateExpiredException
//   - EjbcaException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - SignRequestException
//   - NotFoundException
//   - UserDoesntFullfillEndEntityProfile
//   - CADoesntExistsException
//   - WaitingForApprovalException
//   - CesecoreException

func (service *EjbcaWS) CvcRequest(request *CvcRequest) (*CvcRequestResponse, error) {
	response := new(CvcRequestResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - MultipleMatchException
//   - UserDataSourceException

func (service *EjbcaWS) DeleteUserDataFromSource(request *DeleteUserDataFromSource) (*DeleteUserDataFromSourceResponse, error) {
	response := new(DeleteUserDataFromSourceResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - NotFoundException
//   - CADoesntExistsException
//   - WaitingForApprovalException

func (service *EjbcaWS) KeyRecover(request *KeyRecover) (*KeyRecoverResponse, error) {
	response := new(KeyRecoverResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - CADoesntExistsException
//   - WaitingForApprovalException

func (service *EjbcaWS) CaRenewCertRequest(request *CaRenewCertRequest) (*CaRenewCertRequestResponse, error) {
	response := new(CaRenewCertRequestResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) AddSubjectToRole(request *AddSubjectToRole) (*AddSubjectToRoleResponse, error) {
	response := new(AddSubjectToRoleResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) RemoveSubjectFromRole(request *RemoveSubjectFromRole) (*RemoveSubjectFromRoleResponse, error) {
	response := new(RemoveSubjectFromRoleResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AlreadyRevokedException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - NotFoundException
//   - CADoesntExistsException
//   - WaitingForApprovalException

func (service *EjbcaWS) RevokeCert(request *RevokeCert) (*RevokeCertResponse, error) {
	response := new(RevokeCertResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) CreateCA(request *CreateCA) (*CreateCAResponse, error) {
	response := new(CreateCAResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - NotFoundException
//   - CADoesntExistsException
//   - CesecoreException

func (service *EjbcaWS) Pkcs10Request(request *Pkcs10Request) (*Pkcs10RequestResponse, error) {
	response := new(Pkcs10RequestResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - CADoesntExistsException

func (service *EjbcaWS) GetLastCAChain(request *GetLastCAChain) (*GetLastCAChainResponse, error) {
	response := new(GetLastCAChainResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException

func (service *EjbcaWS) ExistsHardToken(request *ExistsHardToken) (*ExistsHardTokenResponse, error) {
	response := new(ExistsHardTokenResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - CADoesntExistsException

func (service *EjbcaWS) GetCertificate(request *GetCertificate) (*GetCertificateResponse, error) {
	response := new(GetCertificateResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) GetAvailableCertificateProfiles(request *GetAvailableCertificateProfiles) (*GetAvailableCertificateProfilesResponse, error) {
	response := new(GetAvailableCertificateProfilesResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - IllegalQueryException
//   - EndEntityProfileNotFoundException

func (service *EjbcaWS) FindUser(request *FindUser) (*FindUserResponse, error) {
	response := new(FindUserResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - UserDataSourceException

func (service *EjbcaWS) FetchUserData(request *FetchUserData) (*FetchUserDataResponse, error) {
	response := new(FetchUserDataResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - NotFoundException
//   - UserDoesntFullfillEndEntityProfile
//   - WaitingForApprovalException

func (service *EjbcaWS) CertificateRequest(request *CertificateRequest) (*CertificateRequestResponse, error) {
	response := new(CertificateRequestResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AlreadyRevokedException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - NotFoundException
//   - CADoesntExistsException
//   - WaitingForApprovalException

func (service *EjbcaWS) RevokeToken(request *RevokeToken) (*RevokeTokenResponse, error) {
	response := new(RevokeTokenResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - WaitingForApprovalException
//   - CesecoreException

func (service *EjbcaWS) CaCertResponse(request *CaCertResponse) (*CaCertResponseResponse, error) {
	response := new(CaCertResponseResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - ApprovalRequestExpiredException
//   - CAOfflineException
//   - ApprovalException
//   - CryptoTokenOfflineException
//   - CADoesntExistsException

func (service *EjbcaWS) CreateCRL(request *CreateCRL) (*CreateCRLResponse, error) {
	response := new(CreateCRLResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) GetLastCertChain(request *GetLastCertChain) (*GetLastCertChainResponse, error) {
	response := new(GetLastCertChainResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - ApprovalRequestExpiredException
//   - ApprovalException

func (service *EjbcaWS) IsApproved(request *IsApproved) (*IsApprovedResponse, error) {
	response := new(IsApprovedResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException

func (service *EjbcaWS) IsAuthorized(request *IsAuthorized) (*IsAuthorizedResponse, error) {
	response := new(IsAuthorizedResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *EjbcaWS) GetEjbcaVersion(request *GetEjbcaVersion) (*GetEjbcaVersionResponse, error) {
	response := new(GetEjbcaVersionResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException

func (service *EjbcaWS) GetCertificatesByExpirationTime(request *GetCertificatesByExpirationTime) (*GetCertificatesByExpirationTimeResponse, error) {
	response := new(GetCertificatesByExpirationTimeResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - CADoesntExistsException

func (service *EjbcaWS) CheckRevokationStatus(request *CheckRevokationStatus) (*CheckRevokationStatusResponse, error) {
	response := new(CheckRevokationStatusResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - RevokeBackDateNotAllowedForProfileException
//   - EjbcaException
//   - AlreadyRevokedException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - DateNotValidException
//   - NotFoundException
//   - CADoesntExistsException
//   - WaitingForApprovalException

func (service *EjbcaWS) RevokeCertBackdated(request *RevokeCertBackdated) (*RevokeCertBackdatedResponse, error) {
	response := new(RevokeCertBackdatedResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - UnknownProfileTypeException

func (service *EjbcaWS) GetProfile(request *GetProfile) (*GetProfileResponse, error) {
	response := new(GetProfileResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) GetAvailableCAsInProfile(request *GetAvailableCAsInProfile) (*GetAvailableCAsInProfileResponse, error) {
	response := new(GetAvailableCAsInProfileResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - CADoesntExistsException

func (service *EjbcaWS) GetHardTokenDatas(request *GetHardTokenDatas) (*GetHardTokenDatasResponse, error) {
	response := new(GetHardTokenDatasResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException

func (service *EjbcaWS) GetCertificatesByExpirationTimeAndIssuer(request *GetCertificatesByExpirationTimeAndIssuer) (*GetCertificatesByExpirationTimeAndIssuerResponse, error) {
	response := new(GetCertificatesByExpirationTimeAndIssuerResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException

func (service *EjbcaWS) GetCertificatesByExpirationTimeAndType(request *GetCertificatesByExpirationTimeAndType) (*GetCertificatesByExpirationTimeAndTypeResponse, error) {
	response := new(GetCertificatesByExpirationTimeAndTypeResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - NotFoundException
//   - CADoesntExistsException
//   - CesecoreException

func (service *EjbcaWS) CrmfRequest(request *CrmfRequest) (*CrmfRequestResponse, error) {
	response := new(CrmfRequestResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - NotFoundException
//   - UserDoesntFullfillEndEntityProfile
//   - CADoesntExistsException
//   - WaitingForApprovalException

func (service *EjbcaWS) SoftTokenRequest(request *SoftTokenRequest) (*SoftTokenRequestResponse, error) {
	response := new(SoftTokenRequestResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - ApprovalRequestExpiredException
//   - NotFoundException
//   - HardTokenDoesntExistsException
//   - CADoesntExistsException
//   - WaitingForApprovalException
//   - ApprovalRequestExecutionException

func (service *EjbcaWS) GetHardTokenData(request *GetHardTokenData) (*GetHardTokenDataResponse, error) {
	response := new(GetHardTokenDataResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - NotFoundException
//   - CADoesntExistsException
//   - CesecoreException

func (service *EjbcaWS) SpkacRequest(request *SpkacRequest) (*SpkacRequestResponse, error) {
	response := new(SpkacRequestResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException

func (service *EjbcaWS) GetPublisherQueueLength(request *GetPublisherQueueLength) (*GetPublisherQueueLengthResponse, error) {
	response := new(GetPublisherQueueLengthResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - HardTokenExistsException
//   - EjbcaException
//   - AuthorizationDeniedException
//   - ApprovalRequestExpiredException
//   - ApprovalException
//   - UserDoesntFullfillEndEntityProfile
//   - CADoesntExistsException
//   - WaitingForApprovalException
//   - ApprovalRequestExecutionException

func (service *EjbcaWS) GenTokenCertificates(request *GenTokenCertificates) (*GenTokenCertificatesResponse, error) {
	response := new(GenTokenCertificatesResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - UserDoesntFullfillEndEntityProfile
//   - CADoesntExistsException
//   - WaitingForApprovalException

func (service *EjbcaWS) EditUser(request *EditUser) (*EditUserResponse, error) {
	response := new(EditUserResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - NotFoundException
//   - CADoesntExistsException

func (service *EjbcaWS) Pkcs12Req(request *Pkcs12Req) (*Pkcs12ReqResponse, error) {
	response := new(Pkcs12ReqResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - CADoesntExistsException

func (service *EjbcaWS) CustomLog(request *CustomLog) (*CustomLogResponse, error) {
	response := new(CustomLogResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) GetAuthorizedEndEntityProfiles(request *GetAuthorizedEndEntityProfiles) (*GetAuthorizedEndEntityProfilesResponse, error) {
	response := new(GetAuthorizedEndEntityProfilesResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AlreadyRevokedException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - NotFoundException
//   - CADoesntExistsException
//   - WaitingForApprovalException

func (service *EjbcaWS) RevokeUser(request *RevokeUser) (*RevokeUserResponse, error) {
	response := new(RevokeUserResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - CADoesntExistsException

func (service *EjbcaWS) GetLatestCRL(request *GetLatestCRL) (*GetLatestCRLResponse, error) {
	response := new(GetLatestCRLResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) CreateCryptoToken(request *CreateCryptoToken) (*CreateCryptoTokenResponse, error) {
	response := new(CreateCryptoTokenResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) GetAvailableCAs(request *GetAvailableCAs) (*GetAvailableCAsResponse, error) {
	response := new(GetAvailableCAsResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - ApprovalException
//   - NotFoundException
//   - CADoesntExistsException
//   - WaitingForApprovalException

func (service *EjbcaWS) KeyRecoverNewest(request *KeyRecoverNewest) (*KeyRecoverNewestResponse, error) {
	response := new(KeyRecoverNewestResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException
//   - PublisherException
//   - CADoesntExistsException

func (service *EjbcaWS) RepublishCertificate(request *RepublishCertificate) (*RepublishCertificateResponse, error) {
	response := new(RepublishCertificateResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// Error can be either of the following types:
//
//   - EjbcaException
//   - AuthorizationDeniedException

func (service *EjbcaWS) FindCerts(request *FindCerts) (*FindCertsResponse, error) {
	response := new(FindCertsResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

var timeout = time.Duration(30 * time.Second)

func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

type SOAPEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`

	Body SOAPBody
}

type SOAPHeader struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`

	Header interface{}
}

type SOAPBody struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`

	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type SOAPFault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`

	Code   string `xml:"faultcode,omitempty"`
	String string `xml:"faultstring,omitempty"`
	Actor  string `xml:"faultactor,omitempty"`
	Detail string `xml:"detail,omitempty"`
}

type BasicAuth struct {
	Login    string
	Password string
}

type SOAPClient struct {
	url  string
	tls  bool
	auth *BasicAuth
}

func (b *SOAPBody) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}

	var (
		token    xml.Token
		err      error
		consumed bool
	)

Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}

		if token == nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && se.Name.Local == "Fault" {
				b.Fault = &SOAPFault{}
				b.Content = nil

				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}

				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}

				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}

	return nil
}

func (f *SOAPFault) Error() string {
	return f.String
}

func NewSOAPClient(url string, tls bool, auth *BasicAuth) *SOAPClient {
	return &SOAPClient{
		url:  url,
		tls:  tls,
		auth: auth,
	}
}

func (s *SOAPClient) Call(soapAction string, request, response interface{}) error {
	envelope := SOAPEnvelope{
	//Header:        SoapHeader{},
	}

	envelope.Body.Content = request
	buffer := new(bytes.Buffer)

	encoder := xml.NewEncoder(buffer)
	//encoder.Indent("  ", "    ")

	if err := encoder.Encode(envelope); err != nil {
		return err
	}

	if err := encoder.Flush(); err != nil {
		return err
	}

	log.Println(buffer.String())

	req, err := http.NewRequest("POST", s.url, buffer)
	if err != nil {
		return err
	}
	if s.auth != nil {
		req.SetBasicAuth(s.auth.Login, s.auth.Password)
	}

	req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	if soapAction != "" {
		req.Header.Add("SOAPAction", soapAction)
	}

	req.Header.Set("User-Agent", "gowsdl/0.1")
	req.Close = true

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.tls,
		},
		Dial: dialTimeout,
	}

	client := &http.Client{Transport: tr}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	rawbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if len(rawbody) == 0 {
		log.Println("empty response")
		return nil
	}

	log.Println(string(rawbody))
	respEnvelope := new(SOAPEnvelope)
	respEnvelope.Body = SOAPBody{Content: response}
	err = xml.Unmarshal(rawbody, respEnvelope)
	if err != nil {
		return err
	}

	fault := respEnvelope.Body.Fault
	if fault != nil {
		return fault
	}

	return nil
}
