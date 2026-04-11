from aiobotocore.client import AioBaseClient


# class S3Service:
#
#     def __init__(self, client:):
#         self.client = client
#
#     async def generate_presigned_url(self, user_id: str, file_id: str, filename: str, content_type: str,
#                                      expires_in: int = 900):
#         object_key = f"{user_id}/{file_id}/{filename}"
#
#         async with self.client() as client:
#             client.generate_presigned_url()

