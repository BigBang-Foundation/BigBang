// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef XENGINE_STRUCTURE_TREE_H
#define XENGINE_STRUCTURE_TREE_H

#include <map>
#include <memory>
#include <set>

namespace xengine
{

template <typename K, typename D>
class CTreeNode
{
public:
    typedef std::shared_ptr<CTreeNode> NodePtr;

    K key;
    D data;
    NodePtr spParent;
    std::set<NodePtr> setChildren;

    CTreeNode()
    {
    }

    CTreeNode(const K& keyIn)
      : key(keyIn)
    {
    }

    CTreeNode(const K& keyIn, const D& dataIn)
      : key(keyIn), data(dataIn)
    {
    }
};

template <typename K, typename D>
class CMultiwayTree
{
public:
    typedef std::shared_ptr<CMultiwayTree> TreePtr;
    typedef typename CTreeNode<K, D>::NodePtr NodePtr;

    NodePtr spRoot;

    CMultiwayTree(NodePtr spRootIn = nullptr)
      : spRoot(spRootIn)
    {
    }

    // postorder traversal
    // walker: bool (*function)(std::weak_ptr<CTreeNode<K, D>>)
    template <typename NodeWalker>
    bool PostorderTraversal(NodeWalker walker)
    {
        NodePtr spNode = spRoot;

        // postorder traversal
        std::stack<NodePtr> st;
        do
        {
            // if spNode != nullptr push and down, or pop and up.
            if (spNode != nullptr)
            {
                if (!spNode->setSubline.empty())
                {
                    st.push(spNode);
                    spNode = *spNode->setSubline.begin();
                    continue;
                }
            }
            else
            {
                spNode = st.top();
                st.pop();
            }

            // call walker
            if (!walker(spNode))
            {
                return false;
            }

            // root or the last child of parent. fetch from stack when next loop
            if (!spNode->spParent || spNode == *spNode->spParent->setSubline.rbegin())
            {
                spNode = nullptr;
            }
            else
            {
                auto it = spNode->spParent->setSubline.find(spNode);
                if (it == spNode->spParent->setSubline.end())
                {
                    return false;
                }
                else
                {
                    spNode = *++it;
                }
            }
        } while (!st.empty());

        return true;
    }
};

template <typename K, typename D>
class CForest
{
public:
    typedef CTreeNode<K, D> Node;
    typedef typename Node::NodePtr NodePtr;
    typedef CMultiwayTree<K, D> Tree;
    typedef typename Tree::TreePtr TreePtr;

    std::map<K, NodePtr> maspNode;
    std::map<K, TreePtr> maspRoot;

    CForest() {}
    ~CForest() {}

    // postorder traversal
    // walker: bool (*function)(std::weak_ptr<CTreeNode<D>>)
    template <typename NodeWalker>
    bool PostorderTraversal(NodeWalker walker)
    {
        for (auto& r : maspRoot)
        {
            if (!r.second->PostorderTraversal(walker))
            {
                return false;
            }
        }
        return true;
    }

    bool CheckInsert(const K& key, const K& parent, K& root, const std::set<K>& setInvalid = std::set<K>())
    {
        if (key == parent)
        {
            return false;
        }

        NodePtr spNode = GetRelation(key);
        if (spNode)
        {
            // already have parent
            if (spNode->spParent)
            {
                return false;
            }

            // cyclic graph
            for (NodePtr sp = GetRelation(parent); sp; sp = sp->spParent)
            {
                if (sp->key == key)
                {
                    return false;
                }

                if (!sp->spParent || (!setInvalid.empty() && (setInvalid.find(sp->key) != setInvalid.end())))
                {
                    root = sp->key;
                    break;
                }
            }
        }
        else
        {
            // get parent root
            for (NodePtr sp = GetRelation(parent); sp; sp = sp->spParent)
            {
                if (!sp->spParent || (!setInvalid.empty() && (setInvalid.find(sp->key) != setInvalid.end())))
                {
                    root = sp->key;
                    break;
                }
            }
        }

        return true;
    }

    bool Insert(const K& key, const K& parent, const D& data)
    {
        K root;
        if (!CheckInsert(key, parent, root))
        {
            return false;
        }

        // parent
        auto im = maspNode.find(parent);
        if (im == maspNode.end())
        {
            im = maspNode.insert(make_pair(parent, NodePtr(new CTreeNode<K, D>(parent)))).first;
            maspRoot.insert(make_pair(parent, TreePtr(new Tree(im->second))));
        }

        // self
        auto it = maspNode.find(key);
        if (it == maspNode.end())
        {
            it = maspNode.insert(make_pair(key, NodePtr(new CTreeNode<K, D>(key, data)))).first;
        }
        else
        {
            maspRoot.erase(key);
        }

        it->second->spParent = im->second;
        im->second->setChildren.insert(it->second);

        return true;
    }

    void RemoveRelation(const K& key)
    {
        auto it = maspNode.find(key);
        if (it == maspNode.end())
        {
            return;
        }

        NodePtr spNode = it->second;
        NodePtr spParent = spNode->spParent;
        if (spParent)
        {
            spParent->setSubline.erase(spNode);
            // parent is root and no subline
            if (spParent->setSubline.empty() && !spParent->spParent)
            {
                maspRoot.erase(spParent->key);
                maspNode.erase(spParent->key);
            }

            spNode->spParent = nullptr;
            if (!spNode->setSubline.empty())
            {
                maspRoot.insert(make_pair(key, TreePtr(new Tree(spNode))));
            }
            else
            {
                maspNode.erase(spParent->key);
            }
        }
    }

    NodePtr GetRelation(const K& key)
    {
        auto it = maspNode.find(key);
        return (it == maspNode.end()) ? nullptr : it->second;
    }

    template <typename F>
    CForest<K, F> Copy()
    {
        typedef typename CTreeNode<K, F>::NodePtr NewNodePtr;
        typedef typename CMultiwayTree<K, F>::TreePtr NewTreePtr;

        CForest<K, F> f;
        PostorderTraversal([&](NodePtr spNode) {
            NewNodePtr spNewNode = NewNodePtr(new CTreeNode<K, F>());
            spNewNode->data = spNode->data;
            spNewNode->key = spNode->key;
            f.maspNode.insert(std::make_pair(spNewNode->key, spNewNode));

            // root
            if (!spNode->spParent)
            {
                NewTreePtr spTreePtr = NewTreePtr(new CMultiwayTree<K, F>(spNewNode));
                f.maspRoot.insert(make_pair(spNewNode->key, spTreePtr));
            }

            // children
            for (auto spChild : spNode->setChildren)
            {
                auto it = f.maspNode.find(spChild->key);
                if (it == f.maspNode.end())
                {
                    return false;
                }
                spNewNode->subsetChildren.insert(it->second);
                it->second->spParent = spNewNode;
            }
            return true;
        });
        return f;
    }

}; // namespace xengine

} // namespace xengine

#endif // XENGINE_STRUCTURE_TREE_H