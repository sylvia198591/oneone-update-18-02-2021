from django.db import models
from django.contrib.auth.models import User
# from django.core.urlresolvers import reverse

# class User(models.Model):
#     def get_absolute_url(self):
#         return reverse('user:upd', kwargs={"User_id": self.pk})
class cuser(models.Model):
    username=models.OneToOneField(User,on_delete=models.CASCADE,primary_key=True,related_name="tag")
    accno = models.IntegerField(unique=True)

    def __str__(self):
        return self.accno

class Publication(models.Model):
    title = models.CharField(max_length=30)

    class Meta:
        ordering = ['title']

    def __str__(self):
        return self.title

class Article(models.Model):
    headline = models.CharField(max_length=100)
    publications = models.ManyToManyField(Publication,related_name="tag1")

    class Meta:
        ordering = ['headline']

    def __str__(self):
        return self.headline


