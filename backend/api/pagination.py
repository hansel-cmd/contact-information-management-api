from rest_framework.pagination import PageNumberPagination

class CustomPagination(PageNumberPagination):
    page_size = 5

    def __init__(self, page_size = 5):
        self.page_size = page_size